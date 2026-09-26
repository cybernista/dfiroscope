using Microsoft.Data.Sqlite;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlDatabaseIntegrityException : Exception
{
    public NsrlDatabaseIntegrityException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

public sealed class NsrlDatabaseSchemaException : Exception
{
    public NsrlDatabaseSchemaException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

public sealed record NsrlDatabaseValidationResult(
    string Version,
    string BuildSet,
    string ReleaseDate,
    bool IntegrityCheckPassed,
    bool SupportedSchema,
    bool ReleaseIdentityMatched);

public sealed class NsrlRdsV3DatabaseValidator
{
    private static readonly IReadOnlyDictionary<string, string[]> RequiredColumns =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["FILE"] = ["sha256", "sha1", "md5", "crc32", "file_name", "file_size", "package_id"],
            ["MFG"] = ["manufacturer_id", "name"],
            ["OS"] = ["operating_system_id", "name", "version", "manufacturer_id"],
            ["PKG"] = ["package_id", "name", "version", "operating_system_id", "manufacturer_id", "language", "application_type"],
            ["VERSION"] = ["version", "build_set", "build_date", "release_date", "description"]
        };

    public async Task<NsrlDatabaseValidationResult> ValidateAsync(
        string databasePath,
        NsrlReleaseDescriptor release,
        CancellationToken cancellationToken)
    {
        try
        {
            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = Path.GetFullPath(databasePath),
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
                Pooling = false
            }.ToString();
            await using var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteNonQueryAsync(connection, "PRAGMA query_only = ON;", cancellationToken).ConfigureAwait(false);
            await ValidateIntegrityAsync(connection, cancellationToken).ConfigureAwait(false);
            await ValidateObjectsAsync(connection, cancellationToken).ConfigureAwait(false);
            foreach (var required in RequiredColumns)
            {
                await ValidateColumnsAsync(connection, required.Key, required.Value, cancellationToken).ConfigureAwait(false);
            }

            var identity = await ReadVersionIdentityAsync(connection, release, cancellationToken).ConfigureAwait(false);
            await ValidateRepresentativeFileAsync(connection, cancellationToken).ConfigureAwait(false);
            return new NsrlDatabaseValidationResult(
                identity.Version,
                identity.BuildSet,
                identity.ReleaseDate,
                IntegrityCheckPassed: true,
                SupportedSchema: true,
                ReleaseIdentityMatched: true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is NsrlDatabaseIntegrityException or NsrlDatabaseSchemaException)
        {
            throw;
        }
        catch (SqliteException ex)
        {
            throw new NsrlDatabaseIntegrityException("The candidate RDSv3 database could not be opened and checked read-only.", ex);
        }
    }

    private static async Task ValidateIntegrityAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA integrity_check;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var rows = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (rows.Count == 8)
            {
                throw new NsrlDatabaseIntegrityException("The RDSv3 SQLite integrity check returned too many diagnostics.");
            }

            rows.Add(reader.IsDBNull(0) ? string.Empty : reader.GetString(0));
        }

        if (rows.Count != 1 || !string.Equals(rows[0], "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new NsrlDatabaseIntegrityException("The RDSv3 SQLite integrity check did not return exactly one 'ok' result.");
        }
    }

    private static async Task ValidateObjectsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var objects = new Dictionary<string, string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            objects[reader.GetString(0)] = reader.GetString(1);
        }

        foreach (var table in RequiredColumns.Keys)
        {
            if (!objects.TryGetValue(table, out var type) || !string.Equals(type, "table", StringComparison.Ordinal))
            {
                throw new NsrlDatabaseSchemaException($"The candidate RDSv3 database is missing required table {table}.");
            }
        }

        if (!objects.TryGetValue("DISTINCT_HASH", out var viewType) || !string.Equals(viewType, "view", StringComparison.Ordinal))
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 database is missing the required DISTINCT_HASH view.");
        }

        if (objects.Count != RequiredColumns.Count + 1)
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 database contains an unsupported table or view.");
        }
    }

    private static async Task ValidateColumnsAsync(
        SqliteConnection connection,
        string table,
        IReadOnlyCollection<string> requiredColumns,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info(\"{table}\");";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var columns = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            columns.Add(reader.GetString(1));
        }

        if (!columns.SetEquals(requiredColumns))
        {
            throw new NsrlDatabaseSchemaException($"The candidate RDSv3 table {table} does not match the supported minimal schema.");
        }
    }

    private static async Task<(string Version, string BuildSet, string ReleaseDate)> ReadVersionIdentityAsync(
        SqliteConnection connection,
        NsrlReleaseDescriptor release,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT version, build_set, CAST(release_date AS TEXT) FROM VERSION WHERE version = $version LIMIT 2;";
        command.Parameters.AddWithValue("$version", release.ReleaseId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 VERSION table does not identify the selected release.");
        }

        var version = reader.GetString(0);
        var buildSet = reader.GetString(1);
        var releaseDate = reader.GetString(2);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 VERSION table ambiguously identifies the selected release.");
        }

        var normalizedBuildSet = new string(buildSet.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
        if (!string.Equals(normalizedBuildSet, "modern", StringComparison.Ordinal))
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 VERSION row is not the Modern build set required by the selected Modern Minimal publication.");
        }

        if (!DateTime.TryParse(
                releaseDate,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var parsedReleaseDate) ||
            parsedReleaseDate.Date != release.ReleaseDateUtc.Date)
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 VERSION row does not match the selected release date.");
        }

        return (version, buildSet, releaseDate);
    }

    private static async Task ValidateRepresentativeFileAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT sha256 FROM FILE LIMIT 1;";
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
        if (value is null || value.Length != 64 || !value.All(Uri.IsHexDigit))
        {
            throw new NsrlDatabaseSchemaException("The candidate RDSv3 FILE table does not contain the expected SHA-256 representation.");
        }
    }

    private static async Task ExecuteNonQueryAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
