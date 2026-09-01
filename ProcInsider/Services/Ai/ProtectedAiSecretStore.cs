using System.IO;
using System.Text.Json;

namespace ProcInsider.Services.Ai;

public sealed class ProtectedAiSecretStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private string _secretPath;

    public ProtectedAiSecretStore(string secretPath)
    {
        _secretPath = secretPath;
    }

    public string SecretPath => _secretPath;

    public bool HasSecret => !string.IsNullOrWhiteSpace(ReadProtectedSecret());

    public void SetPath(string secretPath)
    {
        _secretPath = secretPath;
    }

    public string LoadSecret()
    {
        var protectedSecret = ReadProtectedSecret();
        if (string.IsNullOrWhiteSpace(protectedSecret))
        {
            return string.Empty;
        }

        return DpapiProtector.UnprotectFromBase64(protectedSecret);
    }

    public void SaveSecret(string secret)
    {
        if (string.IsNullOrWhiteSpace(_secretPath))
        {
            throw new InvalidOperationException("AI secret path is not configured.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_secretPath) ?? AppContext.BaseDirectory);
        var payload = new SecretFile
        {
            Version = 1,
            ProtectedApiKey = DpapiProtector.ProtectToBase64(secret),
            UpdatedUtc = DateTime.UtcNow
        };
        File.WriteAllText(_secretPath, JsonSerializer.Serialize(payload, JsonOptions));
    }

    public void ClearSecret()
    {
        if (!string.IsNullOrWhiteSpace(_secretPath) && File.Exists(_secretPath))
        {
            File.Delete(_secretPath);
        }
    }

    private string ReadProtectedSecret()
    {
        if (string.IsNullOrWhiteSpace(_secretPath) || !File.Exists(_secretPath))
        {
            return string.Empty;
        }

        try
        {
            var payload = JsonSerializer.Deserialize<SecretFile>(File.ReadAllText(_secretPath), JsonOptions);
            return payload?.ProtectedApiKey ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private sealed class SecretFile
    {
        public int Version { get; init; }
        public string ProtectedApiKey { get; init; } = string.Empty;
        public DateTime UpdatedUtc { get; init; }
    }
}
