using Microsoft.Data.Sqlite;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Services.Infrastructure;

/// <summary>
/// Server-local operational enrollment state. It stores only salted token verifiers and
/// public credential metadata in server-control.sqlite3; it is not evidence, audit, case,
/// annotation or private-key authority.
/// </summary>
public sealed class SqliteInfrastructureEnrollmentStateStore : IInfrastructureEnrollmentStateStore
{
    private const int MaximumEnrollmentFailures = 5;
    private static readonly TimeSpan MaximumEnrollmentLifetime = TimeSpan.FromMinutes(15);
    private readonly string _databasePath;

    public SqliteInfrastructureEnrollmentStateStore(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath) || !Path.IsPathFullyQualified(databasePath))
        {
            throw new ArgumentException("The Server operational-control database path must be fully qualified.",
                nameof(databasePath));
        }

        _databasePath = Path.GetFullPath(databasePath);
    }

    public void Initialize()
    {
        var directory = Path.GetDirectoryName(_databasePath) ??
                        throw new InvalidOperationException("The operational-control database has no parent directory.");
        Directory.CreateDirectory(directory);
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS InfrastructureEnrollmentTokens (
                TokenId TEXT PRIMARY KEY,
                IdentityKind INTEGER NOT NULL,
                IdentityId TEXT NOT NULL,
                AgentId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ViewerUserId TEXT NOT NULL,
                ServerUri TEXT NOT NULL,
                AuthorityChainSha256 TEXT NOT NULL,
                Salt BLOB NOT NULL,
                TokenHash BLOB NOT NULL,
                CreatedAtUtcTicks INTEGER NOT NULL,
                ExpiresAtUtcTicks INTEGER NOT NULL,
                FailedAttempts INTEGER NOT NULL,
                UsedAtUtcTicks INTEGER NULL,
                LockedAtUtcTicks INTEGER NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS InfrastructureCredentials (
                IdentityId TEXT NOT NULL,
                CertificateSha256 TEXT NOT NULL,
                IdentityKind INTEGER NOT NULL,
                AgentId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ViewerUserId TEXT NOT NULL,
                ViewerEnabled INTEGER NOT NULL,
                ViewerRole INTEGER NOT NULL,
                LifecycleState INTEGER NOT NULL,
                CredentialEpoch INTEGER NOT NULL,
                CertificateProfileOid TEXT NOT NULL,
                IssuerId TEXT NOT NULL,
                NotBeforeUtcTicks INTEGER NOT NULL,
                NotAfterUtcTicks INTEGER NOT NULL,
                ServerUri TEXT NOT NULL,
                ProtocolGeneration INTEGER NOT NULL,
                ReleaseId TEXT NOT NULL,
                UpdatedAtUtcTicks INTEGER NOT NULL,
                PRIMARY KEY (IdentityId, CertificateSha256)
            ) WITHOUT ROWID;
            CREATE UNIQUE INDEX IF NOT EXISTS IX_InfrastructureCredentials_ActiveIdentity
                ON InfrastructureCredentials (IdentityId)
                WHERE LifecycleState = 1;
            """;
        command.ExecuteNonQuery();
    }

    public void CreateToken(InfrastructureEnrollmentTokenRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (string.IsNullOrWhiteSpace(record.TokenId) || record.TokenId.Length > 128 ||
            !InfrastructureAuthenticationPolicy.IsValidTarget(record.Target) ||
            record.Salt.Length != InfrastructureEnrollmentTokenHash.SaltLength ||
            record.TokenHash.Length != InfrastructureEnrollmentTokenHash.HashLength ||
            record.CreatedAtUtc.Kind != DateTimeKind.Utc || record.ExpiresAtUtc.Kind != DateTimeKind.Utc ||
            record.ExpiresAtUtc <= record.CreatedAtUtc ||
            record.ExpiresAtUtc - record.CreatedAtUtc > MaximumEnrollmentLifetime ||
            record.FailedAttempts != 0 || record.UsedAtUtc != null || record.LockedAtUtc != null)
        {
            throw new InvalidOperationException("The enrollment-token record is malformed or exceeds fixed bounds.");
        }

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO InfrastructureEnrollmentTokens (
                TokenId, IdentityKind, IdentityId, AgentId, HostId, ViewerUserId,
                ServerUri, AuthorityChainSha256, Salt, TokenHash, CreatedAtUtcTicks,
                ExpiresAtUtcTicks, FailedAttempts, UsedAtUtcTicks, LockedAtUtcTicks)
            VALUES (
                $tokenId, $identityKind, $identityId, $agentId, $hostId, $viewerUserId,
                $serverUri, $authorityChainSha256, $salt, $tokenHash, $created,
                $expires, 0, NULL, NULL);
            """;
        command.Parameters.AddWithValue("$tokenId", record.TokenId);
        command.Parameters.AddWithValue("$identityKind", (int)record.Target.IdentityKind);
        command.Parameters.AddWithValue("$identityId", record.Target.IdentityId);
        command.Parameters.AddWithValue("$agentId", record.Target.AgentId);
        command.Parameters.AddWithValue("$hostId", record.Target.HostId);
        command.Parameters.AddWithValue("$viewerUserId", record.Target.ViewerUserId);
        command.Parameters.AddWithValue("$serverUri", record.Target.ServerUri);
        command.Parameters.AddWithValue("$authorityChainSha256", record.Target.AuthorityChainSha256);
        command.Parameters.Add("$salt", SqliteType.Blob).Value = record.Salt;
        command.Parameters.Add("$tokenHash", SqliteType.Blob).Value = record.TokenHash;
        command.Parameters.AddWithValue("$created", record.CreatedAtUtc.Ticks);
        command.Parameters.AddWithValue("$expires", record.ExpiresAtUtc.Ticks);
        command.ExecuteNonQuery();
    }

    public InfrastructureEnrollmentRedemption RedeemToken(
        string tokenId,
        ReadOnlySpan<byte> token,
        DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(tokenId) || token.Length != InfrastructureEnrollmentToken.ByteLength ||
            nowUtc.Kind != DateTimeKind.Utc)
        {
            return new InfrastructureEnrollmentRedemption(
                InfrastructureEnrollmentRedemptionOutcome.TokenInvalid, null, 0);
        }

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        var record = ReadToken(connection, transaction, tokenId);
        if (record == null)
        {
            transaction.Commit();
            return new InfrastructureEnrollmentRedemption(
                InfrastructureEnrollmentRedemptionOutcome.TokenUnknown, null, 0);
        }

        if (record.UsedAtUtc != null)
        {
            transaction.Commit();
            return new InfrastructureEnrollmentRedemption(
                InfrastructureEnrollmentRedemptionOutcome.TokenAlreadyUsed, null, record.FailedAttempts);
        }

        if (record.LockedAtUtc != null || record.FailedAttempts >= MaximumEnrollmentFailures)
        {
            transaction.Commit();
            return new InfrastructureEnrollmentRedemption(
                InfrastructureEnrollmentRedemptionOutcome.TokenLocked, null, record.FailedAttempts);
        }

        if (nowUtc >= record.ExpiresAtUtc)
        {
            transaction.Commit();
            return new InfrastructureEnrollmentRedemption(
                InfrastructureEnrollmentRedemptionOutcome.TokenExpired, null, record.FailedAttempts);
        }

        if (!InfrastructureEnrollmentTokenHash.Verify(record.Salt, token, record.TokenHash))
        {
            var failures = checked(record.FailedAttempts + 1);
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE InfrastructureEnrollmentTokens
                SET FailedAttempts = $failures,
                    LockedAtUtcTicks = CASE WHEN $failures >= 5 THEN $now ELSE NULL END
                WHERE TokenId = $tokenId;
                """;
            update.Parameters.AddWithValue("$failures", failures);
            update.Parameters.AddWithValue("$now", nowUtc.Ticks);
            update.Parameters.AddWithValue("$tokenId", tokenId);
            update.ExecuteNonQuery();
            transaction.Commit();
            return new InfrastructureEnrollmentRedemption(
                failures >= MaximumEnrollmentFailures
                    ? InfrastructureEnrollmentRedemptionOutcome.TokenLocked
                    : InfrastructureEnrollmentRedemptionOutcome.TokenInvalid,
                null,
                failures);
        }

        using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE InfrastructureEnrollmentTokens
                SET UsedAtUtcTicks = $now
                WHERE TokenId = $tokenId AND UsedAtUtcTicks IS NULL AND LockedAtUtcTicks IS NULL;
                """;
            update.Parameters.AddWithValue("$now", nowUtc.Ticks);
            update.Parameters.AddWithValue("$tokenId", tokenId);
            if (update.ExecuteNonQuery() != 1)
            {
                transaction.Rollback();
                return new InfrastructureEnrollmentRedemption(
                    InfrastructureEnrollmentRedemptionOutcome.TokenAlreadyUsed, null, record.FailedAttempts);
            }
        }

        transaction.Commit();
        return new InfrastructureEnrollmentRedemption(
            InfrastructureEnrollmentRedemptionOutcome.Redeemed,
            record.Target with { },
            record.FailedAttempts);
    }

    public InfrastructureCredentialRecord? FindCredential(string identityId, string certificateSha256)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = CredentialSelect +
                              " WHERE IdentityId = $identityId AND CertificateSha256 = $sha256;";
        command.Parameters.AddWithValue("$identityId", identityId);
        command.Parameters.AddWithValue("$sha256", certificateSha256);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadCredential(reader) : null;
    }

    public InfrastructureCredentialRecord? FindActiveCredential(string identityId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = CredentialSelect +
                              " WHERE IdentityId = $identityId AND LifecycleState = 1;";
        command.Parameters.AddWithValue("$identityId", identityId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadCredential(reader) : null;
    }

    public InfrastructureCredentialRecord? FindLatestCredential(string identityId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = CredentialSelect +
                              " WHERE IdentityId = $identityId ORDER BY CredentialEpoch DESC LIMIT 1;";
        command.Parameters.AddWithValue("$identityId", identityId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadCredential(reader) : null;
    }

    public void AddInitialCredential(InfrastructureCredentialRecord credential)
    {
        ValidateCredential(credential, expectedEpoch: 1);
        if (credential.State != InfrastructureCredentialLifecycleState.Active)
        {
            throw new InvalidOperationException("An initial credential must begin Active.");
        }

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var current = connection.CreateCommand())
        {
            current.Transaction = transaction;
            current.CommandText = "SELECT COUNT(*) FROM InfrastructureCredentials WHERE IdentityId = $identityId;";
            current.Parameters.AddWithValue("$identityId", credential.IdentityId);
            if (Convert.ToInt64(current.ExecuteScalar()) != 0)
            {
                throw new InvalidOperationException("The identity is already enrolled and requires explicit rotation or re-enrollment.");
            }
        }

        InsertCredential(connection, transaction, credential);
        transaction.Commit();
    }

    public bool TryRotateCredential(
        string identityId,
        long expectedCurrentEpoch,
        InfrastructureCredentialRecord replacement,
        DateTime nowUtc)
    {
        ValidateUtc(nowUtc);
        ValidateCredential(replacement, checked(expectedCurrentEpoch + 1));
        if (replacement.State != InfrastructureCredentialLifecycleState.Active ||
            !string.Equals(identityId, replacement.IdentityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("A replacement credential must be the next Active epoch for the exact identity.");
        }

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var retire = connection.CreateCommand())
        {
            retire.Transaction = transaction;
            retire.CommandText = """
                UPDATE InfrastructureCredentials
                SET LifecycleState = $rotated, UpdatedAtUtcTicks = $updated
                WHERE IdentityId = $identityId AND CredentialEpoch = $epoch AND LifecycleState = $active;
                """;
            retire.Parameters.AddWithValue("$rotated", (int)InfrastructureCredentialLifecycleState.Rotated);
            retire.Parameters.AddWithValue("$updated", nowUtc.Ticks);
            retire.Parameters.AddWithValue("$identityId", identityId);
            retire.Parameters.AddWithValue("$epoch", expectedCurrentEpoch);
            retire.Parameters.AddWithValue("$active", (int)InfrastructureCredentialLifecycleState.Active);
            if (retire.ExecuteNonQuery() != 1)
            {
                transaction.Rollback();
                return false;
            }
        }

        InsertCredential(connection, transaction, replacement);
        transaction.Commit();
        return true;
    }

    public bool TryReenrollCredential(
        string identityId,
        long expectedTerminalEpoch,
        InfrastructureCredentialRecord replacement,
        DateTime nowUtc)
    {
        ValidateUtc(nowUtc);
        ValidateCredential(replacement, checked(expectedTerminalEpoch + 1));
        if (replacement.State != InfrastructureCredentialLifecycleState.Active ||
            !string.Equals(identityId, replacement.IdentityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Re-enrollment must create the next Active epoch for the exact identity.");
        }

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var terminal = connection.CreateCommand())
        {
            terminal.Transaction = transaction;
            terminal.CommandText = """
                SELECT LifecycleState FROM InfrastructureCredentials
                WHERE IdentityId = $identityId AND CredentialEpoch = $epoch;
                """;
            terminal.Parameters.AddWithValue("$identityId", identityId);
            terminal.Parameters.AddWithValue("$epoch", expectedTerminalEpoch);
            var value = terminal.ExecuteScalar();
            var state = value == null ? InfrastructureCredentialLifecycleState.Unknown :
                (InfrastructureCredentialLifecycleState)Convert.ToInt32(value);
            if (state is not (InfrastructureCredentialLifecycleState.Revoked or
                InfrastructureCredentialLifecycleState.Compromised or
                InfrastructureCredentialLifecycleState.Expired))
            {
                transaction.Rollback();
                return false;
            }
        }

        InsertCredential(connection, transaction, replacement);
        transaction.Commit();
        return true;
    }

    public bool TrySetViewerIdentity(
        string identityId,
        long expectedCredentialEpoch,
        bool enabled,
        InfrastructureViewerRole role,
        DateTime nowUtc)
    {
        ValidateUtc(nowUtc);
        if (enabled && role == InfrastructureViewerRole.Unknown)
        {
            throw new InvalidOperationException("An enabled Viewer requires one bounded role.");
        }

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE InfrastructureCredentials
            SET ViewerEnabled = $enabled, ViewerRole = $role, UpdatedAtUtcTicks = $updated
            WHERE IdentityId = $identityId AND CredentialEpoch = $epoch
              AND IdentityKind = $viewer AND LifecycleState = $active;
            """;
        command.Parameters.AddWithValue("$enabled", enabled ? 1 : 0);
        command.Parameters.AddWithValue("$role", (int)(enabled ? role : InfrastructureViewerRole.Unknown));
        command.Parameters.AddWithValue("$updated", nowUtc.Ticks);
        command.Parameters.AddWithValue("$identityId", identityId);
        command.Parameters.AddWithValue("$epoch", expectedCredentialEpoch);
        command.Parameters.AddWithValue("$viewer", (int)InfrastructureIdentityKind.ViewerUser);
        command.Parameters.AddWithValue("$active", (int)InfrastructureCredentialLifecycleState.Active);
        return command.ExecuteNonQuery() == 1;
    }

    public bool TrySetCredentialState(
        string identityId,
        long expectedCredentialEpoch,
        InfrastructureCredentialLifecycleState state,
        DateTime nowUtc)
    {
        ValidateUtc(nowUtc);
        if (state is not (InfrastructureCredentialLifecycleState.Revoked or
            InfrastructureCredentialLifecycleState.Compromised or
            InfrastructureCredentialLifecycleState.Expired))
        {
            throw new InvalidOperationException("Only terminal credential states may be applied explicitly.");
        }

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE InfrastructureCredentials
            SET LifecycleState = $state, UpdatedAtUtcTicks = $updated
            WHERE IdentityId = $identityId AND CredentialEpoch = $epoch AND LifecycleState = $active;
            """;
        command.Parameters.AddWithValue("$state", (int)state);
        command.Parameters.AddWithValue("$updated", nowUtc.Ticks);
        command.Parameters.AddWithValue("$identityId", identityId);
        command.Parameters.AddWithValue("$epoch", expectedCredentialEpoch);
        command.Parameters.AddWithValue("$active", (int)InfrastructureCredentialLifecycleState.Active);
        return command.ExecuteNonQuery() == 1;
    }

    private SqliteConnection Open()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        return connection;
    }

    private static InfrastructureEnrollmentTokenRecord? ReadToken(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string tokenId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT IdentityKind, IdentityId, AgentId, HostId, ViewerUserId, ServerUri,
                   AuthorityChainSha256, Salt, TokenHash, CreatedAtUtcTicks, ExpiresAtUtcTicks,
                   FailedAttempts, UsedAtUtcTicks, LockedAtUtcTicks
            FROM InfrastructureEnrollmentTokens WHERE TokenId = $tokenId;
            """;
        command.Parameters.AddWithValue("$tokenId", tokenId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new InfrastructureEnrollmentTokenRecord
        {
            TokenId = tokenId,
            Target = new InfrastructureEnrollmentTarget
            {
                IdentityKind = (InfrastructureIdentityKind)reader.GetInt32(0),
                IdentityId = reader.GetString(1),
                AgentId = reader.GetString(2),
                HostId = reader.GetString(3),
                ViewerUserId = reader.GetString(4),
                ServerUri = reader.GetString(5),
                AuthorityChainSha256 = reader.GetString(6)
            },
            Salt = (byte[])reader.GetValue(7),
            TokenHash = (byte[])reader.GetValue(8),
            CreatedAtUtc = Utc(reader.GetInt64(9)),
            ExpiresAtUtc = Utc(reader.GetInt64(10)),
            FailedAttempts = reader.GetInt32(11),
            UsedAtUtc = reader.IsDBNull(12) ? null : Utc(reader.GetInt64(12)),
            LockedAtUtc = reader.IsDBNull(13) ? null : Utc(reader.GetInt64(13))
        };
    }

    private const string CredentialSelect = """
        SELECT IdentityKind, IdentityId, AgentId, HostId, ViewerUserId, ViewerEnabled,
               ViewerRole, LifecycleState, CredentialEpoch, CertificateSha256,
               CertificateProfileOid, IssuerId, NotBeforeUtcTicks, NotAfterUtcTicks,
               ServerUri, ProtocolGeneration, ReleaseId, UpdatedAtUtcTicks
        FROM InfrastructureCredentials
        """;

    private static InfrastructureCredentialRecord ReadCredential(SqliteDataReader reader) => new()
    {
        IdentityKind = (InfrastructureIdentityKind)reader.GetInt32(0),
        IdentityId = reader.GetString(1),
        AgentId = reader.GetString(2),
        HostId = reader.GetString(3),
        ViewerUserId = reader.GetString(4),
        ViewerEnabled = reader.GetInt32(5) != 0,
        ViewerRole = (InfrastructureViewerRole)reader.GetInt32(6),
        State = (InfrastructureCredentialLifecycleState)reader.GetInt32(7),
        CredentialEpoch = reader.GetInt64(8),
        CertificateSha256 = reader.GetString(9),
        CertificateProfileOid = reader.GetString(10),
        IssuerId = reader.GetString(11),
        NotBeforeUtc = Utc(reader.GetInt64(12)),
        NotAfterUtc = Utc(reader.GetInt64(13)),
        ServerUri = reader.GetString(14),
        ProtocolGeneration = reader.GetInt32(15),
        ReleaseId = reader.GetString(16),
        UpdatedAtUtc = Utc(reader.GetInt64(17))
    };

    private static void InsertCredential(
        SqliteConnection connection,
        SqliteTransaction transaction,
        InfrastructureCredentialRecord credential)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO InfrastructureCredentials (
                IdentityId, CertificateSha256, IdentityKind, AgentId, HostId, ViewerUserId,
                ViewerEnabled, ViewerRole, LifecycleState, CredentialEpoch,
                CertificateProfileOid, IssuerId, NotBeforeUtcTicks, NotAfterUtcTicks,
                ServerUri, ProtocolGeneration, ReleaseId, UpdatedAtUtcTicks)
            VALUES (
                $identityId, $sha256, $identityKind, $agentId, $hostId, $viewerUserId,
                $viewerEnabled, $viewerRole, $state, $epoch, $profile, $issuer,
                $notBefore, $notAfter, $serverUri, $protocol, $release, $updated);
            """;
        insert.Parameters.AddWithValue("$identityId", credential.IdentityId);
        insert.Parameters.AddWithValue("$sha256", credential.CertificateSha256);
        insert.Parameters.AddWithValue("$identityKind", (int)credential.IdentityKind);
        insert.Parameters.AddWithValue("$agentId", credential.AgentId);
        insert.Parameters.AddWithValue("$hostId", credential.HostId);
        insert.Parameters.AddWithValue("$viewerUserId", credential.ViewerUserId);
        insert.Parameters.AddWithValue("$viewerEnabled", credential.ViewerEnabled ? 1 : 0);
        insert.Parameters.AddWithValue("$viewerRole", (int)credential.ViewerRole);
        insert.Parameters.AddWithValue("$state", (int)credential.State);
        insert.Parameters.AddWithValue("$epoch", credential.CredentialEpoch);
        insert.Parameters.AddWithValue("$profile", credential.CertificateProfileOid);
        insert.Parameters.AddWithValue("$issuer", credential.IssuerId);
        insert.Parameters.AddWithValue("$notBefore", credential.NotBeforeUtc.Ticks);
        insert.Parameters.AddWithValue("$notAfter", credential.NotAfterUtc.Ticks);
        insert.Parameters.AddWithValue("$serverUri", credential.ServerUri);
        insert.Parameters.AddWithValue("$protocol", credential.ProtocolGeneration);
        insert.Parameters.AddWithValue("$release", credential.ReleaseId);
        insert.Parameters.AddWithValue("$updated", credential.UpdatedAtUtc.Ticks);
        insert.ExecuteNonQuery();
    }

    private static void ValidateCredential(InfrastructureCredentialRecord credential, long expectedEpoch)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (!InfrastructureCredentialLifecyclePolicy.IsCredentialLifetimeAllowed(
                credential.IdentityKind,
                credential.NotBeforeUtc,
                credential.NotAfterUtc) ||
            string.IsNullOrWhiteSpace(credential.IdentityId) || credential.IdentityId.Length > 512 ||
            credential.CredentialEpoch != expectedEpoch || expectedEpoch <= 0 ||
            credential.CertificateSha256.Length != 64 || !credential.CertificateSha256.All(Uri.IsHexDigit) ||
            !string.Equals(
                credential.CertificateProfileOid,
                InfrastructureCertificateProfiles.ForIdentity(credential.IdentityKind),
                StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(credential.IssuerId) || credential.IssuerId.Length > 512 ||
            credential.NotBeforeUtc.Kind != DateTimeKind.Utc || credential.NotAfterUtc.Kind != DateTimeKind.Utc ||
            credential.UpdatedAtUtc.Kind != DateTimeKind.Utc ||
            !Uri.TryCreate(credential.ServerUri, UriKind.Absolute, out var serverUri) ||
            !string.Equals(serverUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            credential.ProtocolGeneration <= 0 || string.IsNullOrWhiteSpace(credential.ReleaseId) ||
            credential.ReleaseId.Length > 512 ||
            (credential.IdentityKind == InfrastructureIdentityKind.AgentService &&
             (string.IsNullOrWhiteSpace(credential.AgentId) || string.IsNullOrWhiteSpace(credential.HostId) ||
              credential.ViewerUserId.Length != 0 || credential.ViewerEnabled ||
              credential.ViewerRole != InfrastructureViewerRole.Unknown)) ||
            (credential.IdentityKind == InfrastructureIdentityKind.ViewerUser &&
             (string.IsNullOrWhiteSpace(credential.ViewerUserId) || credential.AgentId.Length != 0 ||
              credential.HostId.Length != 0 || credential.ViewerEnabled ||
              credential.ViewerRole != InfrastructureViewerRole.Unknown)))
        {
            throw new InvalidOperationException("The credential metadata violates the fixed enrollment/profile/lifetime boundary.");
        }
    }

    private static void ValidateUtc(DateTime value)
    {
        if (value.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("A UTC timestamp is required.", nameof(value));
        }
    }

    private static DateTime Utc(long ticks) => new(ticks, DateTimeKind.Utc);
}
