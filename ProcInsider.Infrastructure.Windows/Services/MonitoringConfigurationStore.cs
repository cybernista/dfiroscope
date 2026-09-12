using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.Services;

/// <summary>
/// Bounded, atomic portable storage shared by reusable form drafts and protected deployment
/// recovery. Callers own the typed configuration areas; paths never come from IPC or file content.
/// </summary>
public sealed class MonitoringConfigurationStore
{
    private const int MaximumBytes = 32 * 1024 * 1024;
    private readonly string _directory;
    private readonly IAgentPairingSecretProtector _protector = new CurrentUserDpapiAgentPairingSecretProtector();
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 64
    };

    public MonitoringConfigurationStore(string? directory = null) =>
        _directory = Path.GetFullPath(directory ?? SessionPathService.GetMonitoringConfigurationDirectory());

    public string DirectoryPath => _directory;

    public static string AutomaticSlot(string sessionRoot, bool windowsSecurity) =>
        "original-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            Path.GetFullPath(sessionRoot).TrimEnd('\\').ToUpperInvariant()))) +
        (windowsSecurity ? "-windows-security" : "-legacy");

    public static string ManualSlot(bool windowsSecurity) =>
        windowsSecurity ? "saved-windows-security" : "saved-legacy";

    public T? Read<T>(string slot) where T : class => ReadCore<T>(slot, protect: true);
    public T? ReadDraft<T>(string slot) where T : class => ReadCore<T>(slot, protect: false);
    public void Write<T>(string slot, T payload) where T : class => WriteCore(slot, payload, protect: true);
    public void WriteOnce<T>(string slot, T payload) where T : class => WriteCore(slot, payload, protect: true, overwrite: false);
    public void WriteDraft<T>(string slot, T payload) where T : class => WriteCore(slot, payload, protect: false);

    public bool HasBackups(string prefix)
    {
        ValidatePath(ResolvePath(prefix, protect: true));
        return Directory.Exists(_directory) &&
            Directory.EnumerateFiles(_directory, prefix + "*.dpapi", SearchOption.TopDirectoryOnly).Any();
    }

    public string CreateAuditPolicyBackupPath()
    {
        var path = Path.Combine(_directory, $"audit-policy-before-monitoring-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}-{Guid.NewGuid():N}.csv");
        ValidatePath(path);
        Directory.CreateDirectory(_directory);
        ValidatePath(path);
        return path;
    }

    private T? ReadCore<T>(string slot, bool protect) where T : class
    {
        var path = ResolvePath(slot, protect);
        ValidatePath(path);
        if (!Directory.Exists(_directory)) return null;
        FileStream stream;
        try { stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (FileNotFoundException) { return null; }
        using var owned = stream;
        if (stream.Length <= 0 || stream.Length > (protect ? MaximumBytes : 256 * 1024))
            throw new InvalidOperationException("Monitoring backup has an invalid size.");
        var encrypted = new byte[(int)stream.Length];
        stream.ReadExactly(encrypted);
        var clear = protect ? _protector.Unprotect(encrypted, Entropy(slot)) : encrypted;
        try
        {
            if (clear.Length > MaximumBytes) throw new InvalidOperationException("Monitoring backup is too large.");
            var envelope = JsonSerializer.Deserialize<Envelope<T>>(clear, Options)
                ?? throw new InvalidOperationException("Monitoring backup is empty.");
            if (envelope.Version != 1 || envelope.Host != (protect ? Environment.MachineName : string.Empty) || envelope.Payload == null)
                throw new InvalidOperationException("Monitoring backup version or host does not match.");
            return envelope.Payload;
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    private void WriteCore<T>(string slot, T payload, bool protect, bool overwrite = true) where T : class
    {
        var path = ResolvePath(slot, protect);
        ValidatePath(path);
        Directory.CreateDirectory(_directory);
        ValidatePath(path);
        var clear = JsonSerializer.SerializeToUtf8Bytes(new Envelope<T>(1, protect ? Environment.MachineName : string.Empty, payload), Options);
        byte[] encrypted;
        try
        {
            if (clear.Length > (protect ? MaximumBytes : 256 * 1024)) throw new InvalidOperationException("Monitoring backup exceeds its size limit.");
            encrypted = protect ? _protector.Protect(clear, Entropy(slot)) : clear.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
        if (encrypted.Length > MaximumBytes) throw new InvalidOperationException("Monitoring backup exceeds its size limit.");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            {
                stream.Write(encrypted);
                stream.Flush(flushToDisk: true);
            }
            ValidatePath(path);
            File.Move(temporary, path, overwrite);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private string ResolvePath(string slot, bool protect)
    {
        if (slot.Length is < 1 or > 160 || slot.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            throw new InvalidOperationException("Invalid monitoring backup slot.");
        return Path.Combine(_directory, slot + (protect ? ".dpapi" : ".json"));
    }

    private static byte[] Entropy(string slot) => SHA256.HashData(Encoding.UTF8.GetBytes(
        "DFIRoscope.MonitoringSnapshot.v1|" + Environment.MachineName + "|" + slot));

    private static void ValidatePath(string path)
    {
        // Reject redirects throughout the ancestry, including nonexistent-leaf creation paths.
        for (var current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Monitoring backup paths cannot traverse reparse points.");
            if (current != path && (attributes & FileAttributes.Directory) == 0)
                throw new InvalidOperationException("Monitoring backup parent is not a directory.");
        }
    }

    private sealed record Envelope<T>(int Version, string Host, T Payload);
}
