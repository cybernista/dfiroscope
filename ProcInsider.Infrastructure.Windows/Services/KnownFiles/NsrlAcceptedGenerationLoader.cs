using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlAcceptedGenerationLoader : INsrlAcceptedGenerationLoader
{
    private const int MaxMetadataBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly string _catalogRoot;
    private readonly string _receiptPath;

    public NsrlAcceptedGenerationLoader(string catalogRoot, string receiptPath)
    {
        _catalogRoot = NormalizeRoot(catalogRoot, "catalog root");
        _receiptPath = Path.GetFullPath(string.IsNullOrWhiteSpace(receiptPath)
            ? throw new ArgumentException("An explicit accepted-generation receipt path is required.", nameof(receiptPath))
            : receiptPath);
        RejectOverlap(_receiptPath, _catalogRoot);
    }

    public async Task<NsrlAcceptedLookupGeneration> LoadAsync(CancellationToken cancellationToken = default)
    {
        var timer = Stopwatch.StartNew();
        var receipt = await ReadBoundedJsonAsync<NsrlAcceptedGenerationReceipt>(_receiptPath, cancellationToken)
            .ConfigureAwait(false);
        ValidateReceiptEnvelope(receipt);

        var artifacts = receipt.Artifacts
            .GroupBy(item => item.Role, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Count() == 1
                    ? group.Single()
                    : throw new InvalidDataException($"The accepted-generation receipt repeats artifact role '{group.Key}'."),
                StringComparer.Ordinal);
        if (artifacts.Count != NsrlAcceptedArtifactRoles.Required.Count ||
            NsrlAcceptedArtifactRoles.Required.Any(role => !artifacts.ContainsKey(role)))
        {
            throw new InvalidDataException("The accepted-generation receipt does not contain the exact required artifact set.");
        }

        var current = new Dictionary<string, (string Path, NsrlAcceptedArtifactIdentity Identity)>(StringComparer.Ordinal);
        foreach (var role in NsrlAcceptedArtifactRoles.Required)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var expected = artifacts[role];
            var path = ResolveContainedFile(_catalogRoot, expected.CatalogRelativePath, role);
            var hashSmall = role is NsrlAcceptedArtifactRoles.ActivePointer or
                NsrlAcceptedArtifactRoles.OfficialManifest or NsrlAcceptedArtifactRoles.DerivedManifest;
            if (hashSmall != !string.IsNullOrWhiteSpace(expected.SmallFileSha256))
            {
                throw new InvalidDataException($"The accepted-generation {role} has an invalid bounded-hash policy.");
            }

            var observed = CaptureArtifact(_catalogRoot, role, path, hashSmall);
            RequireSameIdentity(expected, observed);
            current.Add(role, (path, observed));
        }

        var pointer = await ReadBoundedJsonAsync<ActivePointer>(
            current[NsrlAcceptedArtifactRoles.ActivePointer].Path,
            cancellationToken).ConfigureAwait(false);
        var sourceManifest = await ReadBoundedJsonAsync<NsrlCatalogGenerationManifest>(
            current[NsrlAcceptedArtifactRoles.OfficialManifest].Path,
            cancellationToken).ConfigureAwait(false);
        var derivedManifest = await ReadBoundedJsonAsync<NsrlDerivedIndexManifest>(
            current[NsrlAcceptedArtifactRoles.DerivedManifest].Path,
            cancellationToken).ConfigureAwait(false);

        ValidateManifestBinding(receipt, pointer, sourceManifest, derivedManifest, current);
        await ValidateFastDatabaseAsync(
            current[NsrlAcceptedArtifactRoles.DerivedDatabase].Path,
            derivedManifest,
            cancellationToken).ConfigureAwait(false);

        var sourceRoot = Path.GetDirectoryName(current[NsrlAcceptedArtifactRoles.OfficialManifest].Path)
            ?? throw new InvalidDataException("The accepted official manifest has no generation root.");
        var derivedRoot = Path.GetDirectoryName(current[NsrlAcceptedArtifactRoles.DerivedManifest].Path)
            ?? throw new InvalidDataException("The accepted derived manifest has no generation root.");
        timer.Stop();
        return new NsrlAcceptedLookupGeneration(
            new NsrlCatalogGeneration(
                sourceManifest.GenerationId,
                sourceRoot,
                current[NsrlAcceptedArtifactRoles.OfficialDatabase].Path,
                current[NsrlAcceptedArtifactRoles.OfficialManifest].Path,
                current[NsrlAcceptedArtifactRoles.OfficialManifest].Identity.SmallFileSha256,
                sourceManifest),
            new NsrlDerivedLookupGeneration(
                derivedManifest.DerivedGenerationId,
                derivedManifest.SourceGenerationId,
                derivedRoot,
                current[NsrlAcceptedArtifactRoles.DerivedDatabase].Path,
                current[NsrlAcceptedArtifactRoles.DerivedManifest].Path,
                current[NsrlAcceptedArtifactRoles.DerivedManifest].Identity.SmallFileSha256,
                derivedManifest),
            receipt,
            timer.Elapsed);
    }

    public static NsrlAcceptedGenerationReceipt SealReceipt(NsrlAcceptedGenerationReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var unsealed = receipt with { ReceiptSha256 = string.Empty };
        var receiptHash = ComputeSha256(JsonSerializer.SerializeToUtf8Bytes(unsealed, JsonOptions));
        return unsealed with { ReceiptSha256 = receiptHash };
    }

    public static async Task WriteReceiptAtomicAsync(
        NsrlAcceptedGenerationReceipt receipt,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var path = Path.GetFullPath(outputPath);
        var parent = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException("The accepted-generation receipt output has no parent directory.");
        Directory.CreateDirectory(parent);
        RejectReparsePath(parent);
        var temporary = Path.Combine(parent, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(SealReceipt(receipt), JsonOptions);
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             64 * 1024,
                             FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public static NsrlAcceptedArtifactIdentity CaptureArtifact(
        string catalogRoot,
        string role,
        string path,
        bool hashSmallFile)
    {
        var root = NormalizeRoot(catalogRoot, "catalog root");
        var fullPath = ResolveContainedFile(root, Path.GetRelativePath(root, Path.GetFullPath(path)), role);
        var info = new FileInfo(fullPath);
        info.Refresh();
        if (!info.Exists)
        {
            throw new InvalidDataException($"The accepted-generation {role} is missing.");
        }

        if (hashSmallFile && (info.Length <= 0 || info.Length > MaxMetadataBytes))
        {
            throw new InvalidDataException($"The accepted-generation {role} is empty or exceeds the metadata bound.");
        }

        return new NsrlAcceptedArtifactIdentity
        {
            Role = role,
            CatalogRelativePath = Path.GetRelativePath(root, fullPath).Replace(Path.DirectorySeparatorChar, '/'),
            Length = info.Length,
            LastWriteUtcTicks = info.LastWriteTimeUtc.Ticks,
            Attributes = info.Attributes,
            FileId = NsrlNativeFileIdentity.TryGet(fullPath) ?? string.Empty,
            SmallFileSha256 = hashSmallFile ? ComputeSha256(File.ReadAllBytes(fullPath)) : string.Empty
        };
    }

    public static string HashSmallFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length <= 0 || info.Length > MaxMetadataBytes)
        {
            throw new InvalidDataException("The metadata file is missing, empty, or exceeds the supported bound.");
        }

        return ComputeSha256(File.ReadAllBytes(path));
    }

    public static string ComputeSha256(ReadOnlySpan<byte> bytes)
        => Convert.ToHexString(SHA256.HashData(bytes));

    public static string NormalizeRoot(string value, string label)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"An explicit {label} is required.");
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
        var pathRoot = Path.GetPathRoot(root);
        if (pathRoot is not null && string.Equals(root, Path.TrimEndingDirectorySeparator(pathRoot), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"A drive/share root cannot be used as the {label}.");
        }

        RejectReparsePath(root);
        return root;
    }

    public static void RejectOverlap(string candidatePath, string catalogRoot)
    {
        var candidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidatePath));
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(catalogRoot));
        if (IsSameOrChild(candidate, root) || IsSameOrChild(root, candidate))
        {
            throw new InvalidDataException("The accepted-generation receipt/report/output must remain outside the NSRL catalog root.");
        }
    }

    private static void ValidateReceiptEnvelope(NsrlAcceptedGenerationReceipt receipt)
    {
        var expectedHash = ComputeSha256(JsonSerializer.SerializeToUtf8Bytes(receipt with { ReceiptSha256 = string.Empty }, JsonOptions));
        if (receipt.SchemaVersion != NsrlAcceptedGenerationReceipt.CurrentSchemaVersion ||
            !string.Equals(receipt.PolicyVersion, NsrlAcceptedGenerationReceipt.CurrentPolicyVersion, StringComparison.Ordinal) ||
            !IsSha256(receipt.ReceiptId) ||
            !string.Equals(receipt.AcceptanceSource, "issue-422-validation-report/v1", StringComparison.Ordinal) ||
            !IsSha256(receipt.SourceReportSha256) ||
            !IsSha256(receipt.ReceiptSha256) ||
            !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(expectedHash), Convert.FromHexString(receipt.ReceiptSha256)) ||
            receipt.AcceptedUtc.Kind != DateTimeKind.Utc ||
            receipt.ValidationCompletedUtc.Kind != DateTimeKind.Utc ||
            !receipt.IntegrityPassed || !receipt.QueryPlansPassed ||
            !receipt.DirectStoreCorrectnessPassed || !receipt.NonmutationPassed ||
            !IsBoundedRequired(receipt.SourceGenerationId) || !IsBoundedRequired(receipt.SourceReleaseId, 128) ||
            !string.Equals(receipt.SourceDataSet, "Modern", StringComparison.Ordinal) ||
            !string.Equals(receipt.SourceProfile, "Minimal", StringComparison.Ordinal) ||
            !IsSha256(receipt.SourceManifestSha256) || !IsSha256(receipt.SourceDatabaseSha256) ||
            !IsSha1(receipt.SourceDatabaseLogicalDigest) ||
            !IsBoundedRequired(receipt.DerivedGenerationId) ||
            !IsSha256(receipt.DerivedManifestSha256) || !IsSha256(receipt.DerivedDatabaseSha256) ||
            !string.Equals(receipt.TransformVersion, NsrlServerProtocol.DerivedTransformVersion, StringComparison.Ordinal) ||
            receipt.DerivedSchemaVersion != NsrlDerivedLookupIndexOptions.CurrentSchemaVersion ||
            receipt.RecordCount < 0 || receipt.DistinctHashCount < 0 || receipt.DistinctHashCount > receipt.RecordCount)
        {
            throw new InvalidDataException("The accepted-generation receipt is incomplete, incompatible, or has an invalid self-identity.");
        }
    }

    private static void RequireSameIdentity(NsrlAcceptedArtifactIdentity expected, NsrlAcceptedArtifactIdentity observed)
    {
        if (expected.Length != observed.Length ||
            expected.LastWriteUtcTicks != observed.LastWriteUtcTicks ||
            expected.Attributes != observed.Attributes ||
            (!string.IsNullOrEmpty(expected.FileId) && !string.Equals(expected.FileId, observed.FileId, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(expected.SmallFileSha256) &&
             !FixedHexEquals(expected.SmallFileSha256, observed.SmallFileSha256)))
        {
            throw new InvalidDataException($"The accepted-generation {expected.Role} no longer matches its cheap immutable receipt identity.");
        }
    }

    private static void ValidateManifestBinding(
        NsrlAcceptedGenerationReceipt receipt,
        ActivePointer pointer,
        NsrlCatalogGenerationManifest source,
        NsrlDerivedIndexManifest derived,
        IReadOnlyDictionary<string, (string Path, NsrlAcceptedArtifactIdentity Identity)> current)
    {
        var sourceDatabase = current[NsrlAcceptedArtifactRoles.OfficialDatabase];
        var derivedDatabase = current[NsrlAcceptedArtifactRoles.DerivedDatabase];
        if (pointer.SchemaVersion != 1 ||
            !string.Equals(pointer.GenerationId, source.GenerationId, StringComparison.Ordinal) ||
            !FixedHexEquals(pointer.ManifestSha256, receipt.SourceManifestSha256) ||
            source.SchemaVersion != NsrlCatalogGenerationManifest.CurrentSchemaVersion ||
            !string.Equals(source.GenerationId, receipt.SourceGenerationId, StringComparison.Ordinal) ||
            !string.Equals(source.ReleaseId, receipt.SourceReleaseId, StringComparison.Ordinal) ||
            !string.Equals(source.DataSet, receipt.SourceDataSet, StringComparison.Ordinal) ||
            !string.Equals(source.Profile, receipt.SourceProfile, StringComparison.Ordinal) ||
            source.DatabaseSizeBytes != sourceDatabase.Identity.Length ||
            !FixedHexEquals(source.ActualDatabaseDigest.Value, receipt.SourceDatabaseLogicalDigest) ||
            sourceDatabase.Identity.SmallFileSha256.Length != 0 || derivedDatabase.Identity.SmallFileSha256.Length != 0 ||
            !FixedHexEquals(current[NsrlAcceptedArtifactRoles.OfficialManifest].Identity.SmallFileSha256, receipt.SourceManifestSha256) ||
            derived.SchemaVersion != NsrlDerivedIndexManifest.CurrentSchemaVersion || !derived.Completed ||
            !string.Equals(derived.DerivedGenerationId, receipt.DerivedGenerationId, StringComparison.Ordinal) ||
            !string.Equals(derived.SourceGenerationId, receipt.SourceGenerationId, StringComparison.Ordinal) ||
            !string.Equals(derived.SourceReleaseId, receipt.SourceReleaseId, StringComparison.Ordinal) ||
            !string.Equals(derived.SourceDataSet, receipt.SourceDataSet, StringComparison.Ordinal) ||
            !string.Equals(derived.SourceProfile, receipt.SourceProfile, StringComparison.Ordinal) ||
            !FixedHexEquals(derived.SourceDatabaseSha256, receipt.SourceDatabaseSha256) ||
            !FixedHexEquals(derived.SourceDatabaseLogicalDigest, receipt.SourceDatabaseLogicalDigest) ||
            !string.Equals(derived.TransformVersion, receipt.TransformVersion, StringComparison.Ordinal) ||
            derived.DerivedSchemaVersion != receipt.DerivedSchemaVersion ||
            !FixedHexEquals(derived.DerivedDatabaseSha256, receipt.DerivedDatabaseSha256) ||
            derived.RecordCount != receipt.RecordCount || derived.DistinctHashCount != receipt.DistinctHashCount ||
            !FixedHexEquals(current[NsrlAcceptedArtifactRoles.DerivedManifest].Identity.SmallFileSha256, receipt.DerivedManifestSha256) ||
            sourceDatabase.Identity.Length <= 0 || derivedDatabase.Identity.Length <= 0)
        {
            throw new InvalidDataException("The active pointer, official manifest, derived manifest, and accepted-generation receipt do not describe one exact generation.");
        }

        var sourceRelative = Path.GetRelativePath(
            Path.GetDirectoryName(current[NsrlAcceptedArtifactRoles.OfficialManifest].Path)!,
            sourceDatabase.Path);
        var derivedRelative = Path.GetRelativePath(
            Path.GetDirectoryName(current[NsrlAcceptedArtifactRoles.DerivedManifest].Path)!,
            derivedDatabase.Path);
        if (!string.Equals(sourceRelative, source.DatabaseRelativePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(derivedRelative, derived.DatabaseRelativePath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The accepted database paths do not match their immutable manifests.");
        }
    }

    private static async Task ValidateFastDatabaseAsync(
        string databasePath,
        NsrlDerivedIndexManifest manifest,
        CancellationToken cancellationToken)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 10
        }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteNonQueryAsync(connection, "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;", cancellationToken).ConfigureAwait(false);

        var expectedMetadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = manifest.DerivedSchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["transformVersion"] = manifest.TransformVersion,
            ["sourceGenerationId"] = manifest.SourceGenerationId,
            ["sourceReleaseId"] = manifest.SourceReleaseId,
            ["recordCount"] = manifest.RecordCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["distinctHashCount"] = manifest.DistinctHashCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        foreach (var item in expectedMetadata)
        {
            await using var metadata = connection.CreateCommand();
            metadata.CommandText = "SELECT Value FROM IndexMetadata WHERE Key = $key;";
            metadata.Parameters.AddWithValue("$key", item.Key);
            var actual = Convert.ToString(await metadata.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
            if (!string.Equals(actual, item.Value, StringComparison.Ordinal))
            {
                throw new InvalidDataException($"The accepted derived database metadata '{item.Key}' does not match its receipt.");
            }
        }

        await using (var schema = connection.CreateCommand())
        {
            schema.CommandText =
                "SELECT type, name FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type, name;";
            var schemaObjects = new List<string>();
            await using var reader = await schema.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                schemaObjects.Add(reader.GetString(0) + ":" + reader.GetString(1));
            }

            string[] expectedSchemaObjects =
            [
                "index:IX_LookupRecords_Sha256",
                "index:IX_LookupRecords_Sha256_Order",
                "table:IndexMetadata",
                "table:LookupRecords"
            ];
            if (!schemaObjects.SequenceEqual(expectedSchemaObjects, StringComparer.Ordinal))
            {
                throw new InvalidDataException("The accepted derived database is missing its exact table/index inventory.");
            }
        }

        var indexMetadataColumns = await ReadPragmaRowsAsync(
            connection,
            "PRAGMA table_info('IndexMetadata');",
            reader => $"{reader.GetString(1)}:{reader.GetString(2).ToUpperInvariant()}:{reader.GetInt32(3)}:{reader.GetInt32(5)}",
            cancellationToken).ConfigureAwait(false);
        if (!indexMetadataColumns.SequenceEqual(
                new[] { "Key:TEXT:1:1", "Value:TEXT:1:0" },
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("The accepted derived IndexMetadata schema is incompatible.");
        }

        var lookupColumns = await ReadPragmaRowsAsync(
            connection,
            "PRAGMA table_info('LookupRecords');",
            reader => $"{reader.GetString(1)}:{reader.GetString(2).ToUpperInvariant()}:{reader.GetInt32(3)}:{reader.GetInt32(5)}",
            cancellationToken).ConfigureAwait(false);
        string[] expectedLookupColumns =
        [
            "Sha256:BLOB:1:0", "FileName:TEXT:1:0", "FileSizeBytes:INTEGER:0:0", "PackageId:INTEGER:1:0",
            "ProductName:TEXT:1:0", "ProductVersion:TEXT:1:0", "Manufacturer:TEXT:1:0",
            "OperatingSystemName:TEXT:1:0", "OperatingSystemVersion:TEXT:1:0", "Language:TEXT:1:0",
            "ApplicationType:TEXT:1:0"
        ];
        if (!lookupColumns.SequenceEqual(expectedLookupColumns, StringComparer.Ordinal))
        {
            throw new InvalidDataException("The accepted derived LookupRecords schema is incompatible.");
        }

        var exactIndexColumns = await ReadPragmaRowsAsync(
            connection,
            "PRAGMA index_info('IX_LookupRecords_Sha256');",
            reader => reader.GetString(2),
            cancellationToken).ConfigureAwait(false);
        var orderIndexColumns = await ReadPragmaRowsAsync(
            connection,
            "PRAGMA index_info('IX_LookupRecords_Sha256_Order');",
            reader => reader.GetString(2),
            cancellationToken).ConfigureAwait(false);
        if (!exactIndexColumns.SequenceEqual(new[] { "Sha256" }, StringComparer.Ordinal) ||
            !orderIndexColumns.SequenceEqual(
                new[] { "Sha256", "ProductName", "ProductVersion", "Manufacturer", "FileName", "PackageId" },
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("The accepted derived database index definitions are incompatible.");
        }

        await NsrlDerivedLookupIndexService.ValidateQueryPlanAsync(databasePath, cancellationToken).ConfigureAwait(false);
        await using var probe = connection.CreateCommand();
        probe.CommandText =
            "SELECT FileName FROM LookupRecords INDEXED BY IX_LookupRecords_Sha256 WHERE Sha256 = zeroblob(32) LIMIT 1;";
        _ = await probe.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<string>> ReadPragmaRowsAsync(
        SqliteConnection connection,
        string sql,
        Func<SqliteDataReader, string> project,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var rows = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(project(reader));
        }

        return rows;
    }

    private static async Task ExecuteNonQueryAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T> ReadBoundedJsonAsync<T>(string path, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length <= 0 || info.Length > MaxMetadataBytes)
        {
            throw new InvalidDataException($"The metadata file '{Path.GetFileName(path)}' is missing, empty, or exceeds {MaxMetadataBytes:N0} bytes.");
        }

        RejectReparsePath(path);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException($"The metadata file '{Path.GetFileName(path)}' is empty.");
    }

    private static string ResolveContainedFile(string root, string relative, string label)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative))
        {
            throw new InvalidDataException($"The accepted-generation {label} path is missing or rooted.");
        }

        var normalizedRelative = relative.Replace('/', Path.DirectorySeparatorChar);
        var candidate = Path.GetFullPath(Path.Combine(root, normalizedRelative));
        if (!IsSameOrChild(candidate, root) || !File.Exists(candidate))
        {
            throw new InvalidDataException($"The accepted-generation {label} path is missing or escapes the catalog root.");
        }

        RejectReparsePath(candidate);
        return candidate;
    }

    private static bool IsSameOrChild(string candidate, string root)
    {
        var normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               normalizedCandidate.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void RejectReparsePath(string path)
    {
        var cursor = File.Exists(path)
            ? new FileInfo(Path.GetFullPath(path)).Directory
            : new DirectoryInfo(Path.GetFullPath(path));
        var existing = new Stack<DirectoryInfo>();
        while (cursor is not null)
        {
            if (cursor.Exists)
            {
                existing.Push(cursor);
            }

            cursor = cursor.Parent;
        }

        while (existing.Count > 0)
        {
            if ((existing.Pop().Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("The accepted-generation path cannot traverse a reparse point.");
            }
        }

        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("The accepted-generation path cannot be a reparse point.");
        }
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool IsSha1(string value) => value.Length == 40 && value.All(Uri.IsHexDigit);

    private static bool IsBoundedRequired(string value, int maximum = 256)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= maximum &&
           value.All(character => !char.IsControl(character));

    private static bool FixedHexEquals(string left, string right)
    {
        if (left.Length == 0 && right.Length == 0)
        {
            return true;
        }

        try
        {
            return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static JsonSerializerOptions CreateJsonOptions() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private sealed class ActivePointer
    {
        public int SchemaVersion { get; init; }

        public string GenerationId { get; init; } = string.Empty;

        public string ManifestSha256 { get; init; } = string.Empty;

        public DateTime UpdatedUtc { get; init; }
    }
}

internal static class NsrlNativeFileIdentity
{
    private const uint FileReadAttributes = 0x80;
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint FileShareDelete = 0x4;
    private const uint OpenExisting = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out ByHandleFileInformation information);

    public static string? TryGet(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        using var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info))
        {
            return null;
        }

        var fileIndex = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        return $"{info.VolumeSerialNumber:X8}:{fileIndex:X16}";
    }
}
