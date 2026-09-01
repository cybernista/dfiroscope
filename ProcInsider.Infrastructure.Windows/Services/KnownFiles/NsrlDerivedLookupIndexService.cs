using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlDerivedLookupIndexOptions
{
    public const int CurrentSchemaVersion = 1;

    public int MaxBatchHashes { get; init; } = 10_000;

    public int MaxRecordsPerHash { get; init; } = 50;

    public int MaxConcurrentLookups { get; init; } = 16;

    public TimeSpan LookupTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

public sealed class NsrlDerivedLookupIndexService
{
    public const string DerivedDirectoryName = "derived";
    public const string DatabaseFileName = "nsrl-sha256-lookup.sqlite3";
    public const string ManifestFileName = "derived-index-manifest.json";

    private const int MaxManifestBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly TimeProvider _timeProvider;

    public NsrlDerivedLookupIndexService(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<NsrlDerivedLookupGeneration> BuildOrOpenAsync(
        NsrlCatalogGeneration source,
        CancellationToken cancellationToken = default)
    {
        ValidateSource(source);
        var sourceSha256 = await ComputeSha256Async(source.DatabasePath, cancellationToken).ConfigureAwait(false);
        var derivedGenerationId = NsrlCatalogPathService.SafeName(
            $"{NsrlServerProtocol.DerivedTransformVersion.Replace('/', '-')}-{sourceSha256[..16]}");
        var derivedParent = Contain(source.GenerationRoot, DerivedDirectoryName);
        var finalRoot = Contain(derivedParent, derivedGenerationId);
        if (Directory.Exists(finalRoot))
        {
            return await ReadAndValidateAsync(source, finalRoot, sourceSha256, cancellationToken).ConfigureAwait(false);
        }

        Directory.CreateDirectory(derivedParent);
        RejectReparsePoint(derivedParent);
        var stagingRoot = Contain(derivedParent, ".staging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingRoot);
        try
        {
            var databasePath = Path.Combine(stagingRoot, DatabaseFileName);
            var counts = await BuildDatabaseAsync(source.DatabasePath, databasePath, source, cancellationToken)
                .ConfigureAwait(false);
            await ValidateQueryPlanAsync(databasePath, cancellationToken).ConfigureAwait(false);
            var derivedSha256 = await ComputeSha256Async(databasePath, cancellationToken).ConfigureAwait(false);
            var manifest = new NsrlDerivedIndexManifest
            {
                Completed = true,
                DerivedGenerationId = derivedGenerationId,
                SourceGenerationId = source.GenerationId,
                SourceReleaseId = source.Manifest.ReleaseId,
                SourceDataSet = source.Manifest.DataSet,
                SourceProfile = source.Manifest.Profile,
                SourceDatabaseSha256 = sourceSha256,
                SourceDatabaseLogicalDigest = source.Manifest.ActualDatabaseDigest.Value,
                DatabaseRelativePath = DatabaseFileName,
                DerivedDatabaseSha256 = derivedSha256,
                RecordCount = counts.RecordCount,
                DistinctHashCount = counts.DistinctHashCount,
                BuiltUtc = _timeProvider.GetUtcNow().UtcDateTime
            };
            var manifestPath = Path.Combine(stagingRoot, ManifestFileName);
            await File.WriteAllTextAsync(
                manifestPath,
                JsonSerializer.Serialize(manifest, JsonOptions),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                cancellationToken).ConfigureAwait(false);
            File.SetAttributes(databasePath, File.GetAttributes(databasePath) | FileAttributes.ReadOnly);
            File.SetAttributes(manifestPath, File.GetAttributes(manifestPath) | FileAttributes.ReadOnly);

            try
            {
                Directory.Move(stagingRoot, finalRoot);
            }
            catch (IOException) when (Directory.Exists(finalRoot))
            {
                DeleteContainedStaging(stagingRoot, derivedParent);
            }

            return await ReadAndValidateAsync(source, finalRoot, sourceSha256, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            DeleteContainedStaging(stagingRoot, derivedParent);
            throw;
        }
    }

    public async Task<NsrlDerivedLookupGeneration> ReadAndValidateAsync(
        NsrlCatalogGeneration source,
        string derivedRoot,
        CancellationToken cancellationToken = default)
    {
        ValidateSource(source);
        var sourceSha256 = await ComputeSha256Async(source.DatabasePath, cancellationToken).ConfigureAwait(false);
        return await ReadAndValidateAsync(source, derivedRoot, sourceSha256, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<NsrlDerivedLookupGeneration> ReadAndValidateAsync(
        NsrlCatalogGeneration source,
        string derivedRoot,
        string sourceSha256,
        CancellationToken cancellationToken)
    {
        var finalRoot = Contain(Path.Combine(source.GenerationRoot, DerivedDirectoryName), Path.GetFileName(derivedRoot));
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(finalRoot),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(derivedRoot)),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The derived NSRL generation path is outside the verified source generation.");
        }

        RejectReparsePoint(finalRoot);
        var manifestPath = Path.Combine(finalRoot, ManifestFileName);
        var manifest = await ReadBoundedManifestAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        if (manifest.SchemaVersion != NsrlDerivedIndexManifest.CurrentSchemaVersion ||
            !manifest.Completed ||
            !string.Equals(manifest.DerivedGenerationId, Path.GetFileName(finalRoot), StringComparison.Ordinal) ||
            !string.Equals(manifest.SourceGenerationId, source.GenerationId, StringComparison.Ordinal) ||
            !string.Equals(manifest.SourceReleaseId, source.Manifest.ReleaseId, StringComparison.Ordinal) ||
            !string.Equals(manifest.SourceDataSet, source.Manifest.DataSet, StringComparison.Ordinal) ||
            !string.Equals(manifest.SourceProfile, source.Manifest.Profile, StringComparison.Ordinal) ||
            !string.Equals(manifest.SourceDatabaseSha256, sourceSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(manifest.SourceDatabaseLogicalDigest, source.Manifest.ActualDatabaseDigest.Value, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(manifest.TransformVersion, NsrlServerProtocol.DerivedTransformVersion, StringComparison.Ordinal) ||
            manifest.DerivedSchemaVersion != NsrlDerivedLookupIndexOptions.CurrentSchemaVersion ||
            !string.Equals(manifest.DatabaseRelativePath, DatabaseFileName, StringComparison.Ordinal) ||
            manifest.RecordCount < 0 ||
            manifest.DistinctHashCount < 0 ||
            manifest.DistinctHashCount > manifest.RecordCount)
        {
            throw new InvalidDataException("The derived NSRL manifest is incomplete, incompatible, or not bound to the active official generation.");
        }

        var databasePath = Contain(finalRoot, manifest.DatabaseRelativePath);
        if (!File.Exists(databasePath) ||
            (File.GetAttributes(databasePath) & FileAttributes.ReadOnly) == 0 ||
            (File.GetAttributes(manifestPath) & FileAttributes.ReadOnly) == 0)
        {
            throw new InvalidDataException("The derived NSRL generation is missing or is not immutable.");
        }

        var actualDerivedHash = await ComputeSha256Async(databasePath, cancellationToken).ConfigureAwait(false);
        if (!FixedHexEquals(manifest.DerivedDatabaseSha256, actualDerivedHash))
        {
            throw new InvalidDataException("The derived NSRL database does not match its immutable manifest.");
        }

        await ValidateDatabaseAsync(databasePath, manifest, cancellationToken).ConfigureAwait(false);
        var manifestSha256 = await ComputeSha256Async(manifestPath, cancellationToken).ConfigureAwait(false);
        return new NsrlDerivedLookupGeneration(
            manifest.DerivedGenerationId,
            source.GenerationId,
            finalRoot,
            databasePath,
            manifestPath,
            manifestSha256,
            manifest);
    }

    private static async Task<(long RecordCount, long DistinctHashCount)> BuildDatabaseAsync(
        string sourcePath,
        string targetPath,
        NsrlCatalogGeneration source,
        CancellationToken cancellationToken)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = targetPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        connection.CreateFunction<string, byte[]?>(
            "dfiro_sha256_blob",
            static value => TryDecodeSha256(value, out var bytes) ? bytes : null,
            isDeterministic: true);
        await ExecuteAsync(connection,
            """
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            PRAGMA temp_store=FILE;
            PRAGMA foreign_keys=OFF;
            CREATE TABLE IndexMetadata (Key TEXT NOT NULL PRIMARY KEY, Value TEXT NOT NULL) WITHOUT ROWID;
            CREATE TABLE LookupRecords (
                Sha256 BLOB NOT NULL CHECK(length(Sha256) = 32),
                FileName TEXT NOT NULL,
                FileSizeBytes INTEGER NULL,
                PackageId INTEGER NOT NULL,
                ProductName TEXT NOT NULL,
                ProductVersion TEXT NOT NULL,
                Manufacturer TEXT NOT NULL,
                OperatingSystemName TEXT NOT NULL,
                OperatingSystemVersion TEXT NOT NULL,
                Language TEXT NOT NULL,
                ApplicationType TEXT NOT NULL);
            """,
            cancellationToken).ConfigureAwait(false);

        await using (var attach = connection.CreateCommand())
        {
            attach.CommandText = "ATTACH DATABASE $source AS official;";
            attach.Parameters.AddWithValue("$source", Path.GetFullPath(sourcePath));
            await attach.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandTimeout = 0;
            insert.CommandText =
                """
                INSERT INTO LookupRecords (
                    Sha256, FileName, FileSizeBytes, PackageId, ProductName, ProductVersion,
                    Manufacturer, OperatingSystemName, OperatingSystemVersion, Language, ApplicationType)
                SELECT DISTINCT
                    dfiro_sha256_blob(f.sha256),
                    COALESCE(f.file_name, ''),
                    f.file_size,
                    COALESCE(f.package_id, 0),
                    COALESCE(p.name, ''),
                    COALESCE(p.version, ''),
                    COALESCE(m.name, ''),
                    COALESCE(o.name, ''),
                    COALESCE(o.version, ''),
                    COALESCE(p.language, ''),
                    COALESCE(p.application_type, '')
                FROM official.FILE AS f
                LEFT JOIN official.PKG AS p ON p.package_id = f.package_id
                LEFT JOIN official.MFG AS m ON m.manufacturer_id = p.manufacturer_id
                LEFT JOIN official.OS AS o ON o.operating_system_id = p.operating_system_id
                WHERE length(f.sha256) = 64 AND dfiro_sha256_blob(f.sha256) IS NOT NULL;
                """;
            await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }

        await ExecuteAsync(connection,
            """
            CREATE INDEX IX_LookupRecords_Sha256 ON LookupRecords(Sha256);
            CREATE INDEX IX_LookupRecords_Sha256_Order
                ON LookupRecords(Sha256, ProductName, ProductVersion, Manufacturer, FileName, PackageId);
            ANALYZE main;
            """,
            cancellationToken).ConfigureAwait(false);

        var recordCount = await ExecuteInt64Async(connection, "SELECT COUNT(*) FROM LookupRecords;", cancellationToken)
            .ConfigureAwait(false);
        var distinctHashCount = await ExecuteInt64Async(
            connection,
            "SELECT COUNT(*) FROM (SELECT 1 FROM LookupRecords GROUP BY Sha256);",
            cancellationToken).ConfigureAwait(false);
        await WriteMetadataAsync(connection, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = NsrlDerivedLookupIndexOptions.CurrentSchemaVersion.ToString(CultureInfo.InvariantCulture),
            ["transformVersion"] = NsrlServerProtocol.DerivedTransformVersion,
            ["sourceGenerationId"] = source.GenerationId,
            ["sourceReleaseId"] = source.Manifest.ReleaseId,
            ["recordCount"] = recordCount.ToString(CultureInfo.InvariantCulture),
            ["distinctHashCount"] = distinctHashCount.ToString(CultureInfo.InvariantCulture)
        }, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "DETACH DATABASE official; PRAGMA optimize;", cancellationToken).ConfigureAwait(false);
        await connection.CloseAsync().ConfigureAwait(false);
        return (recordCount, distinctHashCount);
    }

    private static async Task ValidateDatabaseAsync(
        string databasePath,
        NsrlDerivedIndexManifest manifest,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenReadOnlyAsync(databasePath, cancellationToken).ConfigureAwait(false);
        var integrity = await ExecuteStringAsync(connection, "PRAGMA integrity_check;", cancellationToken).ConfigureAwait(false);
        if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The derived NSRL database failed SQLite integrity validation.");
        }

        var recordCount = await ExecuteInt64Async(connection, "SELECT COUNT(*) FROM LookupRecords;", cancellationToken)
            .ConfigureAwait(false);
        var distinctHashCount = await ExecuteInt64Async(
            connection,
            "SELECT COUNT(*) FROM (SELECT 1 FROM LookupRecords GROUP BY Sha256);",
            cancellationToken).ConfigureAwait(false);
        if (recordCount != manifest.RecordCount || distinctHashCount != manifest.DistinctHashCount)
        {
            throw new InvalidDataException("The derived NSRL database counts do not match its manifest.");
        }

        var transform = await ReadMetadataAsync(connection, "transformVersion", cancellationToken).ConfigureAwait(false);
        var sourceGeneration = await ReadMetadataAsync(connection, "sourceGenerationId", cancellationToken).ConfigureAwait(false);
        if (!string.Equals(transform, manifest.TransformVersion, StringComparison.Ordinal) ||
            !string.Equals(sourceGeneration, manifest.SourceGenerationId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The derived NSRL database metadata does not match its manifest.");
        }

        await ValidateQueryPlanAsync(connection, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task ValidateQueryPlanAsync(string databasePath, CancellationToken cancellationToken)
    {
        await using var connection = await OpenReadOnlyAsync(databasePath, cancellationToken).ConfigureAwait(false);
        await ValidateQueryPlanAsync(connection, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ValidateQueryPlanAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            "EXPLAIN QUERY PLAN SELECT FileName FROM LookupRecords INDEXED BY IX_LookupRecords_Sha256 WHERE Sha256 = $hash;";
        command.Parameters.Add("$hash", SqliteType.Blob).Value = new byte[32];
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var details = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            details.Add(reader.GetString(3));
        }

        if (details.Count == 0 || details.Any(detail => detail.Contains("SCAN LookupRecords", StringComparison.OrdinalIgnoreCase)) ||
            !details.Any(detail => detail.Contains("IX_LookupRecords_Sha256", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException("The derived NSRL lookup plan does not use the exact SHA-256 index.");
        }
    }

    private static async Task WriteMetadataAsync(
        SqliteConnection connection,
        IReadOnlyDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = "INSERT INTO IndexMetadata(Key, Value) VALUES ($key, $value);";
        var key = command.Parameters.Add("$key", SqliteType.Text);
        var value = command.Parameters.Add("$value", SqliteType.Text);
        foreach (var pair in values.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            key.Value = pair.Key;
            value.Value = pair.Value;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ReadMetadataAsync(
        SqliteConnection connection,
        string key,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT Value FROM IndexMetadata WHERE Key = $key;";
        command.Parameters.AddWithValue("$key", key);
        return Convert.ToString(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture)
            ?? string.Empty;
    }

    private static async Task<NsrlDerivedIndexManifest> ReadBoundedManifestAsync(
        string path,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            throw new InvalidDataException("The derived NSRL manifest is missing.");
        }

        var length = new FileInfo(path).Length;
        if (length <= 0 || length > MaxManifestBytes)
        {
            throw new InvalidDataException("The derived NSRL manifest is empty or oversized.");
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await JsonSerializer.DeserializeAsync<NsrlDerivedIndexManifest>(stream, JsonOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException("The derived NSRL manifest could not be parsed.");
    }

    private static async Task<SqliteConnection> OpenReadOnlyAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(path),
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY;", cancellationToken)
            .ConfigureAwait(false);
        return connection;
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.CommandTimeout = 0;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<long> ExecuteInt64Async(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    private static async Task<string> ExecuteStringAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToString(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture)
            ?? string.Empty;
    }

    private static void ValidateSource(NsrlCatalogGeneration source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (string.IsNullOrWhiteSpace(source.GenerationId) ||
            !Directory.Exists(source.GenerationRoot) ||
            !File.Exists(source.DatabasePath) ||
            !File.Exists(source.ManifestPath) ||
            (File.GetAttributes(source.DatabasePath) & FileAttributes.ReadOnly) == 0 ||
            source.Manifest.SchemaVersion != NsrlCatalogGenerationManifest.CurrentSchemaVersion ||
            !string.Equals(source.Manifest.GenerationId, source.GenerationId, StringComparison.Ordinal) ||
            !string.Equals(source.Manifest.DataSet, "Modern", StringComparison.Ordinal) ||
            !string.Equals(source.Manifest.Profile, "Minimal", StringComparison.Ordinal) ||
            !string.Equals(source.Manifest.PublicationKind, "FullSql", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The derived index requires one complete verified immutable Modern Minimal generation.");
        }
    }

    private static string Contain(string root, string relative)
    {
        if (Path.IsPathRooted(relative))
        {
            throw new InvalidDataException("A derived NSRL path cannot be rooted.");
        }

        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var candidate = Path.GetFullPath(Path.Combine(fullRoot, relative));
        if (!candidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("A derived NSRL path escapes the verified source generation.");
        }

        return candidate;
    }

    private static void RejectReparsePoint(string path)
    {
        if (!Directory.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("A derived NSRL path is missing or traverses a reparse point.");
        }
    }

    private static void DeleteContainedStaging(string stagingRoot, string parent)
    {
        try
        {
            var fullParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
            var fullStaging = Path.GetFullPath(stagingRoot);
            if (!fullStaging.StartsWith(fullParent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(fullStaging).StartsWith(".staging-", StringComparison.Ordinal))
            {
                return;
            }

            if (Directory.Exists(fullStaging))
            {
                foreach (var file in Directory.EnumerateFiles(fullStaging, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                Directory.Delete(fullStaging, recursive: true);
            }
        }
        catch
        {
            // A contained failed derivative may remain for diagnosis; completed generations are never touched here.
        }
    }

    internal static bool TryDecodeSha256(string? value, out byte[] bytes)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            bytes = [];
            return false;
        }

        bytes = Convert.FromHexString(normalized);
        return true;
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var digest = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(digest);
    }

    private static bool FixedHexEquals(string expected, string actual)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(expected),
                Convert.FromHexString(actual));
        }
        catch (FormatException)
        {
            return false;
        }
    }

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
}

public sealed class NsrlIndexedLookupStore : IDisposable
{
    private readonly NsrlDerivedLookupGeneration _generation;
    private readonly NsrlDerivedLookupIndexOptions _options;
    private readonly SemaphoreSlim _lookupGate;

    public NsrlIndexedLookupStore(
        NsrlDerivedLookupGeneration generation,
        NsrlDerivedLookupIndexOptions? options = null)
    {
        _generation = generation ?? throw new ArgumentNullException(nameof(generation));
        _options = options ?? new NsrlDerivedLookupIndexOptions();
        if (_options.MaxBatchHashes is < 1 or > 10_000 ||
            _options.MaxRecordsPerHash is < 1 or > 500 ||
            _options.MaxConcurrentLookups is < 1 or > 128 ||
            _options.LookupTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The managed NSRL lookup bounds are invalid.");
        }

        _lookupGate = new SemaphoreSlim(_options.MaxConcurrentLookups, _options.MaxConcurrentLookups);
    }

    public NsrlDerivedLookupGeneration Generation => _generation;

    public async Task<NsrlLookupItemResult> LookupAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        var response = await LookupBatchAsync([sha256], cancellationToken).ConfigureAwait(false);
        return response.Results[0];
    }

    public async Task<NsrlBatchLookupResponse> LookupBatchAsync(
        IReadOnlyList<string> hashes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hashes);
        if (hashes.Count == 0 || hashes.Count > _options.MaxBatchHashes)
        {
            throw new InvalidDataException($"A batch must contain between 1 and {_options.MaxBatchHashes:N0} SHA-256 values.");
        }

        var startedUtc = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.LookupTimeout);
        await _lookupGate.WaitAsync(timeout.Token).ConfigureAwait(false);
        try
        {
            var results = hashes.Select((hash, ordinal) => new MutableLookupResult(ordinal, hash)).ToArray();
            var valid = new List<(int Ordinal, byte[] Hash)>();
            foreach (var result in results)
            {
                if (!NsrlDerivedLookupIndexService.TryDecodeSha256(result.Input, out var bytes))
                {
                    result.Status = NsrlLookupItemStatus.Invalid;
                    result.Detail = "The value is not an exact 64-character hexadecimal SHA-256.";
                    continue;
                }

                result.Normalized = Convert.ToHexString(bytes).ToLowerInvariant();
                result.Status = NsrlLookupItemStatus.Error;
                result.Detail = "The exact lookup did not produce a terminal result.";
                valid.Add((result.Ordinal, bytes));
            }

            var commandCount = 0;
            if (valid.Count > 0)
            {
                await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = _generation.DatabasePath,
                    Mode = SqliteOpenMode.ReadOnly,
                    Cache = SqliteCacheMode.Private,
                    Pooling = false
                }.ToString());
                await connection.OpenAsync(timeout.Token).ConfigureAwait(false);
                await using (var setup = connection.CreateCommand())
                {
                    var sql = new StringBuilder(
                        "CREATE TEMP TABLE InputHashes(Ordinal INTEGER NOT NULL PRIMARY KEY, Sha256 BLOB NOT NULL); INSERT INTO InputHashes(Ordinal, Sha256) VALUES ");
                    for (var index = 0; index < valid.Count; index++)
                    {
                        if (index > 0)
                        {
                            sql.Append(',');
                        }

                        sql.Append("($o").Append(index).Append(",$h").Append(index).Append(')');
                        setup.Parameters.AddWithValue("$o" + index.ToString(CultureInfo.InvariantCulture), valid[index].Ordinal);
                        setup.Parameters.Add("$h" + index.ToString(CultureInfo.InvariantCulture), SqliteType.Blob).Value = valid[index].Hash;
                    }

                    sql.Append(';');
                    setup.CommandText = sql.ToString();
                    setup.CommandTimeout = checked((int)Math.Ceiling(_options.LookupTimeout.TotalSeconds));
                    await setup.ExecuteNonQueryAsync(timeout.Token).ConfigureAwait(false);
                    commandCount++;
                }

                await using (var query = connection.CreateCommand())
                {
                    query.CommandText =
                        """
                        SELECT Ordinal, Sha256, FileName, FileSizeBytes, PackageId, ProductName, ProductVersion,
                               Manufacturer, OperatingSystemName, OperatingSystemVersion, Language, ApplicationType,
                               TotalForHash, RowForHash
                        FROM (
                            SELECT i.Ordinal,
                                   lower(hex(i.Sha256)) AS Sha256,
                                   r.FileName, r.FileSizeBytes, r.PackageId, r.ProductName, r.ProductVersion,
                                   r.Manufacturer, r.OperatingSystemName, r.OperatingSystemVersion, r.Language, r.ApplicationType,
                                   COUNT(r.Sha256) OVER (PARTITION BY i.Ordinal) AS TotalForHash,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY i.Ordinal
                                       ORDER BY r.ProductName, r.ProductVersion, r.Manufacturer, r.FileName, r.PackageId,
                                                r.OperatingSystemName, r.OperatingSystemVersion, r.Language, r.ApplicationType) AS RowForHash
                            FROM InputHashes AS i
                            LEFT JOIN LookupRecords AS r INDEXED BY IX_LookupRecords_Sha256 ON r.Sha256 = i.Sha256
                        )
                        WHERE RowForHash <= $rowLimit
                        ORDER BY Ordinal, RowForHash;
                        """;
                    query.Parameters.AddWithValue("$rowLimit", _options.MaxRecordsPerHash + 1);
                    query.CommandTimeout = checked((int)Math.Ceiling(_options.LookupTimeout.TotalSeconds));
                    await using var reader = await query.ExecuteReaderAsync(timeout.Token).ConfigureAwait(false);
                    while (await reader.ReadAsync(timeout.Token).ConfigureAwait(false))
                    {
                        var result = results[reader.GetInt32(0)];
                        result.TotalRecordCount = reader.GetInt32(12);
                        if (result.TotalRecordCount == 0 || reader.IsDBNull(2))
                        {
                            result.Status = NsrlLookupItemStatus.NoMatch;
                            result.Detail = "No exact SHA-256 match was present in the active NIST RDS generation.";
                            continue;
                        }

                        result.Status = NsrlLookupItemStatus.Match;
                        result.Detail = "Present in the active NIST RDS generation; this is not a benign or authorization verdict.";
                        if (result.Records.Count < _options.MaxRecordsPerHash)
                        {
                            result.Records.Add(new NsrlLookupRecord
                            {
                                Sha256 = reader.GetString(1),
                                FileName = Bound(reader.GetString(2)),
                                FileSizeBytes = reader.IsDBNull(3) ? null : reader.GetInt64(3),
                                PackageId = reader.GetInt64(4),
                                ProductName = Bound(reader.GetString(5)),
                                ProductVersion = Bound(reader.GetString(6)),
                                Manufacturer = Bound(reader.GetString(7)),
                                OperatingSystemName = Bound(reader.GetString(8)),
                                OperatingSystemVersion = Bound(reader.GetString(9)),
                                Language = Bound(reader.GetString(10)),
                                ApplicationType = Bound(reader.GetString(11)),
                                ProviderSource = $"NIST NSRL {Bound(_generation.Manifest.SourceReleaseId)} Modern Minimal"
                            });
                        }
                    }

                    commandCount++;
                }
            }

            stopwatch.Stop();
            return new NsrlBatchLookupResponse
            {
                CatalogVersion = _generation.Manifest.SourceReleaseId,
                GenerationId = _generation.SourceGenerationId,
                DatabaseCommandCount = commandCount,
                LookupUtc = startedUtc,
                Elapsed = stopwatch.Elapsed,
                Results = results.Select(result => result.ToImmutable()).ToArray()
            };
        }
        finally
        {
            _lookupGate.Release();
        }
    }

    public async Task<IReadOnlyList<string>> GetQueryPlanAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _generation.DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            "EXPLAIN QUERY PLAN SELECT * FROM LookupRecords INDEXED BY IX_LookupRecords_Sha256 WHERE Sha256 = $hash;";
        command.Parameters.Add("$hash", SqliteType.Blob).Value = new byte[32];
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var details = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            details.Add(Bound(reader.GetString(3)));
        }

        return details;
    }

    public async Task<IReadOnlyList<string>> GetSampleHashesAsync(
        int count,
        CancellationToken cancellationToken = default)
    {
        if (count is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _generation.DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT lower(hex(Sha256)) FROM LookupRecords GROUP BY Sha256 ORDER BY Sha256 LIMIT $count;";
        command.Parameters.AddWithValue("$count", count);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var hashes = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            hashes.Add(reader.GetString(0));
        }

        return hashes;
    }

    public void Dispose()
    {
        _lookupGate.Dispose();
    }

    private static string Bound(string value)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        return trimmed.Length <= 1024 ? trimmed : trimmed[..1024];
    }

    private sealed class MutableLookupResult
    {
        public MutableLookupResult(int ordinal, string input)
        {
            Ordinal = ordinal;
            Input = input ?? string.Empty;
            Normalized = Input.Trim().ToLowerInvariant();
        }

        public int Ordinal { get; }

        public string Input { get; }

        public string Normalized { get; set; }

        public NsrlLookupItemStatus Status { get; set; }

        public string Detail { get; set; } = string.Empty;

        public int TotalRecordCount { get; set; }

        public List<NsrlLookupRecord> Records { get; } = [];

        public NsrlLookupItemResult ToImmutable() => new()
        {
            Ordinal = Ordinal,
            Sha256 = Normalized,
            Status = Status,
            Detail = Detail,
            TotalRecordCount = TotalRecordCount,
            IsTruncated = TotalRecordCount > Records.Count,
            Records = Records.ToArray()
        };
    }
}
