using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace ProcInsider.Services.KnownFiles;

/// <summary>
/// Computes the logical SQLite schema-and-content SHA-1 emitted by SQLite's dbhash utility.
/// </summary>
public static class NsrlSqliteDbHash
{
    private static readonly byte[] NullPrefix = "0"u8.ToArray();
    private static readonly byte[] IntegerPrefix = "1"u8.ToArray();
    private static readonly byte[] FloatPrefix = "2"u8.ToArray();
    private static readonly byte[] TextPrefix = "3"u8.ToArray();
    private static readonly byte[] BlobPrefix = "4"u8.ToArray();

    public static async Task<string> ComputeAsync(string databasePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(databasePath),
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString();

        try
        {
            await using var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteNonQueryAsync(connection, "PRAGMA query_only = ON;", cancellationToken).ConfigureAwait(false);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

            var tables = await ReadTableNamesAsync(connection, cancellationToken).ConfigureAwait(false);
            foreach (var table in tables)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var quotedTable = '"' + table.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
                await HashQueryAsync(connection, hash, $"SELECT * FROM {quotedTable};", cancellationToken).ConfigureAwait(false);
            }

            await HashQueryAsync(
                connection,
                hash,
                "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE tbl_name LIKE '%' ORDER BY name COLLATE nocase;",
                cancellationToken).ConfigureAwait(false);
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SqliteException ex)
        {
            throw new NsrlDatabaseIntegrityException("The candidate RDSv3 database could not be hashed with the SQLite dbhash content algorithm.", ex);
        }
    }

    private static async Task<IReadOnlyList<string>> ReadTableNamesAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT name FROM sqlite_schema " +
            "WHERE type='table' AND sql NOT LIKE 'CREATE VIRTUAL%' " +
            "AND name NOT LIKE 'sqlite_%' AND name LIKE '%' " +
            "ORDER BY name COLLATE nocase;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var tables = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            tables.Add(reader.GetString(0));
        }

        return tables;
    }

    private static async Task HashQueryAsync(
        SqliteConnection connection,
        IncrementalHash hash,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            for (var index = 0; index < reader.FieldCount; index++)
            {
                AppendValue(hash, reader.GetValue(index));
            }
        }
    }

    private static void AppendValue(IncrementalHash hash, object value)
    {
        switch (value)
        {
            case DBNull:
                hash.AppendData(NullPrefix);
                return;
            case long integer:
            {
                Span<byte> bytes = stackalloc byte[sizeof(long)];
                BinaryPrimitives.WriteInt64BigEndian(bytes, integer);
                hash.AppendData(IntegerPrefix);
                hash.AppendData(bytes);
                return;
            }
            case double floatingPoint:
            {
                Span<byte> bytes = stackalloc byte[sizeof(long)];
                BinaryPrimitives.WriteInt64BigEndian(bytes, BitConverter.DoubleToInt64Bits(floatingPoint));
                hash.AppendData(FloatPrefix);
                hash.AppendData(bytes);
                return;
            }
            case string text:
                hash.AppendData(TextPrefix);
                AppendUtf8(hash, text);
                return;
            case byte[] blob:
                hash.AppendData(BlobPrefix);
                hash.AppendData(blob);
                return;
            default:
                throw new NsrlDatabaseIntegrityException($"SQLite dbhash encountered unsupported value type {value.GetType().Name}.");
        }
    }

    private static void AppendUtf8(IncrementalHash hash, string text)
    {
        var byteCount = Encoding.UTF8.GetByteCount(text);
        byte[]? rented = null;
        Span<byte> bytes = byteCount <= 512
            ? stackalloc byte[byteCount]
            : (rented = ArrayPool<byte>.Shared.Rent(byteCount));
        try
        {
            var written = Encoding.UTF8.GetBytes(text.AsSpan(), bytes);
            hash.AppendData(bytes[..written]);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
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
