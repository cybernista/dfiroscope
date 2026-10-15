using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProcInsider.Services.Ai;

/// <summary>
/// A password encrypts the complete collection of current-user DPAPI ciphertexts. The
/// unwrapped key exists only while this Viewer instance is explicitly unlocked.
/// </summary>
public sealed class ProtectedAiSecretStore
{
    private const int VaultVersion = 3;
    private const int KdfIterations = 310_000;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private string _secretPath;
    private string? _vaultPath;
    private bool _allowLegacySecretMigration;
    private string _legacyDefaultScope = "legacy-unbound";
    private byte[]? _unlockedKey;

    public ProtectedAiSecretStore(string secretPath, string? vaultPath = null,
        bool allowLegacySecretMigration = false)
    {
        _secretPath = secretPath;
        _vaultPath = vaultPath;
        _allowLegacySecretMigration = allowLegacySecretMigration;
        _legacyDefaultScope = vaultPath is null ? "legacy-unbound" : string.Empty;
    }

    public string SecretPath => _vaultPath ?? _secretPath;
    public string LegacySecretPath => _secretPath;
    public bool IsPasswordConfigured => ReadVaultFile() is not null;
    public bool IsUnlocked => _unlockedKey is not null;
    public bool AllowsLegacyMigration => _allowLegacySecretMigration;
    public bool HasSecret => ReadLegacyEntries().Count > 0 || (ReadVaultFile()?.Scopes.Count ?? 0) > 0;

    public void SetPath(string secretPath)
    {
        _secretPath = secretPath;
        _legacyDefaultScope = _vaultPath is null ? "legacy-unbound" : string.Empty;
    }

    public void SetPaths(string secretPath, string vaultPath, bool allowLegacySecretMigration = false)
    {
        if (!string.Equals(_vaultPath, vaultPath, StringComparison.OrdinalIgnoreCase)) Lock();
        _secretPath = secretPath;
        _vaultPath = vaultPath;
        _allowLegacySecretMigration = allowLegacySecretMigration;
        _legacyDefaultScope = string.Empty;
    }

    public void BindLegacyScope(string scope)
    {
        if (_vaultPath is not null)
        {
            // The original session settings are the only authority for an unscoped key.
            // Clear a prior session's binding when this session has no valid scope.
            _legacyDefaultScope = string.IsNullOrWhiteSpace(scope) ? string.Empty : scope;
            return;
        }
        _legacyDefaultScope = string.IsNullOrWhiteSpace(scope) ? "legacy-unbound" : scope;
        var legacy = ReadLegacyFile();
        if (legacy is null || !string.IsNullOrEmpty(legacy.Scope)) return;
        legacy.Scope = _legacyDefaultScope;
        legacy.Version = 2;
        AiSettingsService.AtomicWrite(_secretPath, JsonSerializer.Serialize(legacy, JsonOptions));
    }

    public void PersistLegacyScope()
    {
        var legacy = ReadLegacyFile();
        if (legacy is null || !string.IsNullOrWhiteSpace(legacy.Scope) ||
            string.IsNullOrWhiteSpace(legacy.ProtectedApiKey)) return;
        if (_vaultPath is not null && !_allowLegacySecretMigration)
            throw new InvalidOperationException("Archived AI key storage is read-only and cannot be migrated.");
        if (_vaultPath is not null && string.IsNullOrWhiteSpace(_legacyDefaultScope))
            throw new InvalidDataException("Unscoped legacy AI key has no valid original session provider and endpoint.");
        legacy.Scope = _legacyDefaultScope;
        legacy.Version = 2;
        AiSettingsService.AtomicWrite(_secretPath, JsonSerializer.Serialize(legacy, JsonOptions));
    }

    public bool HasSecretFor(string scope)
    {
        if (string.IsNullOrWhiteSpace(scope)) return false;
        var vault = ReadVaultFile();
        if (vault is not null)
        {
            if (_unlockedKey is not null && DecryptVault(vault, _unlockedKey).ContainsKey(scope)) return true;
            if (_unlockedKey is null && vault.Scopes.Contains(scope, StringComparer.Ordinal)) return true;
        }
        return ReadLegacyEntries().ContainsKey(scope);
    }

    public string LoadSecret()
    {
        if (_vaultPath is not null)
            throw new InvalidOperationException("Direct legacy AI key access is unavailable with password-protected storage.");
        return DpapiProtector.UnprotectFromBase64(ReadLegacyFile()?.ProtectedApiKey ?? string.Empty);
    }

    public string LoadSecretFor(string scope)
    {
        if (string.IsNullOrWhiteSpace(scope)) return string.Empty;
        var vault = ReadVaultFile();
        if (vault is not null)
        {
            if (_unlockedKey is null) throw new InvalidOperationException("AI key storage is locked.");
            if (_allowLegacySecretMigration && File.Exists(_secretPath))
            {
                MigrateLegacyIntoVault();
                vault = ReadVaultFile()!;
            }
            var entries = DecryptVault(vault, _unlockedKey);
            if (!_allowLegacySecretMigration && ReadLegacyEntries().TryGetValue(scope, out var archivedCipher))
            {
                if (!entries.TryGetValue(scope, out var currentCipher))
                    throw new InvalidOperationException("This archived AI key is unavailable until migrated from a writable session.");
                if (DpapiProtector.UnprotectFromBase64(currentCipher) !=
                    DpapiProtector.UnprotectFromBase64(archivedCipher))
                    throw new InvalidDataException("This archived AI key conflicts with the application key for this endpoint.");
            }
            return entries.TryGetValue(scope, out var cipher)
                ? DpapiProtector.UnprotectFromBase64(cipher) : string.Empty;
        }
        if (_vaultPath is not null && File.Exists(_secretPath))
            throw new InvalidOperationException(_allowLegacySecretMigration
                ? "Set an AI key-storage password before using saved keys."
                : "This archived AI key is unavailable until migrated from a writable session.");
        var legacy = ReadLegacyEntries();
        return legacy.TryGetValue(scope, out var value)
            ? DpapiProtector.UnprotectFromBase64(value) : string.Empty;
    }

    public void InitializePassword(string password)
    {
        EnsureVaultPath();
        if (File.Exists(_vaultPath)) throw new InvalidOperationException("AI key-storage password already exists.");
        if (!_allowLegacySecretMigration && File.Exists(_secretPath))
            throw new InvalidOperationException("Archived AI key storage is read-only and cannot be migrated.");
        var entries = ReadLegacyEntries();
        VerifyDpapiEntries(entries);
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = DeriveKey(password, salt, KdfIterations);
        try
        {
            WriteAndVerifyVault(entries, key, salt, KdfIterations);
            if (File.Exists(_secretPath)) File.Delete(_secretPath);
            Lock();
            _unlockedKey = key;
            key = Array.Empty<byte>();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public bool Unlock(string password)
    {
        EnsureVaultPath();
        Lock();
        var vault = ReadVaultFile() ?? throw new InvalidOperationException("AI key-storage password is not configured.");
        var key = DeriveKey(password, Convert.FromBase64String(vault.Salt), vault.Iterations);
        try
        {
            try { DecryptVault(vault, key); }
            catch (AuthenticationTagMismatchException) { return false; }
            _unlockedKey = key;
            key = Array.Empty<byte>();
            MigrateLegacyIntoVault();
            return true;
        }
        catch
        {
            Lock();
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public void Lock()
    {
        if (_unlockedKey is null) return;
        CryptographicOperations.ZeroMemory(_unlockedKey);
        _unlockedKey = null;
    }

    public void ChangePassword(string oldPassword, string newPassword)
    {
        EnsureVaultPath();
        if (!Unlock(oldPassword))
            throw new InvalidOperationException("The old AI key-storage password is incorrect or storage is damaged.");
        var vault = ReadVaultFile()!;
        var oldKey = _unlockedKey!;
        try
        {
            var entries = DecryptVault(vault, oldKey);
            var salt = RandomNumberGenerator.GetBytes(16);
            var newKey = DeriveKey(newPassword, salt, KdfIterations);
            try
            {
                WriteAndVerifyVault(entries, newKey, salt, KdfIterations);
                Lock();
                _unlockedKey = newKey;
                newKey = Array.Empty<byte>();
            }
            finally { CryptographicOperations.ZeroMemory(newKey); }
        }
        finally
        {
            if (!ReferenceEquals(oldKey, _unlockedKey)) CryptographicOperations.ZeroMemory(oldKey);
        }
    }

    public void SaveSecret(string secret) => SaveSecret(secret, string.Empty);

    public void SaveSecret(string secret, string scope)
    {
        if (_vaultPath is not null)
        {
            if (string.IsNullOrWhiteSpace(scope)) throw new InvalidOperationException("AI key scope is required.");
            if (_allowLegacySecretMigration && File.Exists(_secretPath)) MigrateLegacyIntoVault();
            var (vault, entries) = ReadUnlockedVault();
            entries[scope] = DpapiProtector.ProtectToBase64(secret);
            WriteAndVerifyVault(entries, _unlockedKey!, Convert.FromBase64String(vault.Salt), vault.Iterations);
            return;
        }
        if (string.IsNullOrWhiteSpace(_secretPath)) throw new InvalidOperationException("AI secret path is not configured.");
        var previous = ReadLegacyFile();
        var others = previous?.OtherSecrets is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(previous.OtherSecrets, StringComparer.Ordinal);
        if (previous is not null && !string.IsNullOrWhiteSpace(previous.Scope) && previous.Scope != scope &&
            !string.IsNullOrWhiteSpace(previous.ProtectedApiKey))
            others[previous.Scope] = previous.ProtectedApiKey;
        others.Remove(scope);
        var payload = new LegacySecretFile
        {
            Version = 2, ProtectedApiKey = DpapiProtector.ProtectToBase64(secret), Scope = scope,
            OtherSecrets = others, UpdatedUtc = DateTime.UtcNow
        };
        AiSettingsService.AtomicWrite(_secretPath, JsonSerializer.Serialize(payload, JsonOptions));
    }

    public void ClearSecret()
    {
        if (_vaultPath is not null)
        {
            if (_allowLegacySecretMigration && File.Exists(_secretPath)) MigrateLegacyIntoVault();
            var (vault, _) = ReadUnlockedVault();
            WriteAndVerifyVault(new Dictionary<string, string>(StringComparer.Ordinal), _unlockedKey!,
                Convert.FromBase64String(vault.Salt), vault.Iterations);
            return;
        }
        if (File.Exists(_secretPath)) File.Delete(_secretPath);
    }

    public void ClearSecretFor(string scope)
    {
        if (string.IsNullOrWhiteSpace(scope)) return;
        if (_vaultPath is not null)
        {
            if (!_allowLegacySecretMigration && ReadLegacyEntries().ContainsKey(scope))
                throw new InvalidOperationException("Archived AI key storage is read-only and cannot be cleared.");
            if (_allowLegacySecretMigration && File.Exists(_secretPath)) MigrateLegacyIntoVault();
            var (vault, entries) = ReadUnlockedVault();
            if (!entries.Remove(scope)) return;
            WriteAndVerifyVault(entries, _unlockedKey!, Convert.FromBase64String(vault.Salt), vault.Iterations);
            return;
        }
        var entriesLegacy = ReadLegacyEntries();
        if (!entriesLegacy.Remove(scope)) return;
        if (entriesLegacy.Count == 0) { ClearSecret(); return; }
        var retained = entriesLegacy.First();
        entriesLegacy.Remove(retained.Key);
        var payload = new LegacySecretFile
        {
            Version = 2, Scope = retained.Key, ProtectedApiKey = retained.Value,
            OtherSecrets = entriesLegacy, UpdatedUtc = DateTime.UtcNow
        };
        AiSettingsService.AtomicWrite(_secretPath, JsonSerializer.Serialize(payload, JsonOptions));
    }

    private void MigrateLegacyIntoVault()
    {
        if (!_allowLegacySecretMigration || !File.Exists(_secretPath)) return;
        var legacy = ReadLegacyEntries();
        VerifyDpapiEntries(legacy);
        var (vault, entries) = ReadUnlockedVault();
        foreach (var (scope, cipher) in legacy)
        {
            if (entries.TryGetValue(scope, out var existing))
            {
                if (DpapiProtector.UnprotectFromBase64(existing) != DpapiProtector.UnprotectFromBase64(cipher))
                    throw new InvalidDataException("A legacy AI key conflicts with an existing vault key.");
            }
            else entries.Add(scope, cipher);
        }
        WriteAndVerifyVault(entries, _unlockedKey!, Convert.FromBase64String(vault.Salt), vault.Iterations);
        File.Delete(_secretPath);
    }

    private (VaultFile Vault, Dictionary<string, string> Entries) ReadUnlockedVault()
    {
        if (_unlockedKey is null) throw new InvalidOperationException("AI key storage is locked.");
        var vault = ReadVaultFile() ?? throw new InvalidDataException("AI key storage is missing.");
        return (vault, DecryptVault(vault, _unlockedKey));
    }

    private void WriteAndVerifyVault(Dictionary<string, string> entries, byte[] key, byte[] salt, int iterations)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(entries, JsonOptions);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        try
        {
            using (var aes = new AesGcm(key, tag.Length)) aes.Encrypt(nonce, plaintext, ciphertext, tag);
            var file = new VaultFile
            {
                Version = VaultVersion, Iterations = iterations, Salt = Convert.ToBase64String(salt),
                Nonce = Convert.ToBase64String(nonce), Tag = Convert.ToBase64String(tag),
                Ciphertext = Convert.ToBase64String(ciphertext),
                Scopes = entries.Keys.Order(StringComparer.Ordinal).ToList()
            };
            AiSettingsService.AtomicWrite(_vaultPath!, JsonSerializer.Serialize(file, JsonOptions));
            var verified = DecryptVault(ReadVaultFile()!, key);
            if (verified.Count != entries.Count || entries.Any(pair =>
                    !verified.TryGetValue(pair.Key, out var value) || value != pair.Value))
                throw new InvalidDataException("AI key storage verification failed.");
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static Dictionary<string, string> DecryptVault(VaultFile vault, byte[] key)
    {
        var ciphertext = Convert.FromBase64String(vault.Ciphertext);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using (var aes = new AesGcm(key, 16))
                aes.Decrypt(Convert.FromBase64String(vault.Nonce), ciphertext,
                    Convert.FromBase64String(vault.Tag), plaintext);
            var entries = JsonSerializer.Deserialize<Dictionary<string, string>>(plaintext)
                ?? throw new InvalidDataException("AI key storage has no entries.");
            if (entries.Count != vault.Scopes.Count ||
                entries.Keys.Any(scope => string.IsNullOrWhiteSpace(scope) || !vault.Scopes.Contains(scope, StringComparer.Ordinal)) ||
                entries.Values.Any(string.IsNullOrWhiteSpace))
                throw new InvalidDataException("AI key storage inventory does not match its encrypted contents.");
            return new Dictionary<string, string>(entries, StringComparer.Ordinal);
        }
        catch (JsonException ex) { throw new InvalidDataException("AI key storage contents are invalid.", ex); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(password ?? throw new ArgumentNullException(nameof(password)), salt,
            iterations, HashAlgorithmName.SHA256, 32);

    private VaultFile? ReadVaultFile()
    {
        if (string.IsNullOrWhiteSpace(_vaultPath) || !File.Exists(_vaultPath)) return null;
        VaultFile file;
        try
        {
            file = JsonSerializer.Deserialize<VaultFile>(File.ReadAllText(_vaultPath), JsonOptions)
                ?? throw new InvalidDataException("AI key storage is empty.");
        }
        catch (JsonException ex) { throw new InvalidDataException("AI key storage is invalid.", ex); }
        try
        {
            if (file.Version != VaultVersion || file.Iterations < 100_000 || file.Iterations > 10_000_000 ||
                Convert.FromBase64String(file.Salt).Length != 16 ||
                Convert.FromBase64String(file.Nonce).Length != 12 ||
                Convert.FromBase64String(file.Tag).Length != 16 || file.Scopes is null ||
                file.Scopes.Any(string.IsNullOrWhiteSpace) ||
                file.Scopes.Distinct(StringComparer.Ordinal).Count() != file.Scopes.Count)
                throw new InvalidDataException("AI key storage header is invalid.");
            Convert.FromBase64String(file.Ciphertext);
        }
        catch (FormatException ex) { throw new InvalidDataException("AI key storage encoding is invalid.", ex); }
        return file;
    }

    private Dictionary<string, string> ReadLegacyEntries()
    {
        var legacy = ReadLegacyFile();
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        if (legacy is null) return entries;
        if (string.IsNullOrWhiteSpace(legacy.ProtectedApiKey) &&
            (!string.IsNullOrWhiteSpace(legacy.Scope) || legacy.OtherSecrets is { Count: > 0 }))
            throw new InvalidDataException("Legacy AI key storage has an empty primary entry.");
        if (!string.IsNullOrWhiteSpace(legacy.ProtectedApiKey))
        {
            if (_vaultPath is not null && string.IsNullOrWhiteSpace(legacy.Scope) &&
                string.IsNullOrWhiteSpace(_legacyDefaultScope))
                throw new InvalidDataException("Unscoped legacy AI key has no valid original session provider and endpoint.");
            entries.Add(string.IsNullOrWhiteSpace(legacy.Scope) ? _legacyDefaultScope : legacy.Scope, legacy.ProtectedApiKey);
        }
        if (legacy.OtherSecrets is not null)
            foreach (var (scope, cipher) in legacy.OtherSecrets)
            {
                if (string.IsNullOrWhiteSpace(scope) || string.IsNullOrWhiteSpace(cipher) || !entries.TryAdd(scope, cipher))
                    throw new InvalidDataException("Legacy AI key storage contains an invalid or duplicate entry.");
            }
        return entries;
    }

    private LegacySecretFile? ReadLegacyFile()
    {
        if (string.IsNullOrWhiteSpace(_secretPath) || !File.Exists(_secretPath)) return null;
        try
        {
            var file = JsonSerializer.Deserialize<LegacySecretFile>(File.ReadAllText(_secretPath), JsonOptions)
                ?? throw new InvalidDataException("Legacy AI key storage is empty.");
            if (file.Version is not (1 or 2) || file.ProtectedApiKey is null)
                throw new InvalidDataException("Legacy AI key storage version or contents are invalid.");
            return file;
        }
        catch (JsonException ex) { throw new InvalidDataException("Legacy AI key storage is invalid.", ex); }
    }

    private static void VerifyDpapiEntries(Dictionary<string, string> entries)
    {
        foreach (var cipher in entries.Values) _ = DpapiProtector.UnprotectFromBase64(cipher);
    }

    private void EnsureVaultPath()
    {
        if (string.IsNullOrWhiteSpace(_vaultPath))
            throw new InvalidOperationException("AI key storage path is not configured.");
    }

    private sealed class LegacySecretFile
    {
        public int Version { get; set; }
        public string ProtectedApiKey { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty;
        public Dictionary<string, string>? OtherSecrets { get; set; }
        public DateTime UpdatedUtc { get; set; }
    }

    private sealed class VaultFile
    {
        public int Version { get; set; }
        public int Iterations { get; set; }
        public string Salt { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string Tag { get; set; } = string.Empty;
        public string Ciphertext { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
    }
}
