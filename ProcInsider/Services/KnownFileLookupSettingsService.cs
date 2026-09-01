using System.IO;
using System.Text;
using System.Text.Json;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services;

public sealed class KnownFileLookupSettingsService
{
    private const int MaxSettingsBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private string _settingsPath;

    public KnownFileLookupSettingsService(string settingsPath = "")
    {
        _settingsPath = settingsPath;
    }

    public string SettingsPath => _settingsPath;

    public void SetPath(string settingsPath)
    {
        _settingsPath = settingsPath ?? string.Empty;
    }

    public KnownFileLookupSettings Load(out string diagnostic)
    {
        diagnostic = string.Empty;
        if (string.IsNullOrWhiteSpace(_settingsPath) || !File.Exists(_settingsPath))
        {
            return Normalize(new KnownFileLookupSettings());
        }

        try
        {
            var file = new FileInfo(_settingsPath);
            if (file.Length > MaxSettingsBytes)
            {
                diagnostic = $"NSRL settings exceed the {MaxSettingsBytes:N0}-byte limit; safe loopback defaults are active.";
                return Normalize(new KnownFileLookupSettings());
            }

            var settings = JsonSerializer.Deserialize<KnownFileLookupSettings>(
                File.ReadAllText(_settingsPath, Encoding.UTF8),
                JsonOptions);
            if (settings == null || settings.SchemaVersion is < 1 or > KnownFileLookupSettings.CurrentSchemaVersion)
            {
                diagnostic = "NSRL settings use an unsupported schema; safe loopback defaults are active.";
                return Normalize(new KnownFileLookupSettings());
            }

            return Normalize(settings);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            diagnostic = $"NSRL settings could not be read ({ex.GetType().Name}); safe loopback defaults are active.";
            return Normalize(new KnownFileLookupSettings());
        }
    }

    public void Save(KnownFileLookupSettings settings)
    {
        if (string.IsNullOrWhiteSpace(_settingsPath))
        {
            throw new InvalidOperationException("The session NSRL settings path is not configured.");
        }

        var normalized = Normalize(settings);
        if (!TryResolveEndpoint(normalized, out _, out var endpointError))
        {
            throw new InvalidOperationException(endpointError);
        }

        var directory = Path.GetDirectoryName(_settingsPath)
            ?? throw new InvalidOperationException("The session NSRL settings path has no containing directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(_settingsPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(
                temporaryPath,
                JsonSerializer.Serialize(normalized, JsonOptions),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temporaryPath, _settingsPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public static KnownFileLookupSettings Normalize(KnownFileLookupSettings settings)
    {
        var normalized = settings.Clone();
        normalized.SchemaVersion = KnownFileLookupSettings.CurrentSchemaVersion;
        if (!Enum.IsDefined(normalized.ProviderMode))
        {
            normalized.ProviderMode = KnownFileLookupProviderMode.ExternalCompatible;
        }
        normalized.Endpoint = string.IsNullOrWhiteSpace(normalized.Endpoint)
            ? KnownFileLookupSettings.DefaultEndpoint
            : normalized.Endpoint.Trim();
        normalized.TimeoutSeconds = Math.Clamp(normalized.TimeoutSeconds, 2, 120);
        normalized.MaxResponseBytes = Math.Clamp(normalized.MaxResponseBytes, 16 * 1024, 4 * 1024 * 1024);
        normalized.MaxRecords = Math.Clamp(normalized.MaxRecords, 1, 100);
        normalized.ManagedCatalogRoot = normalized.ManagedCatalogRoot?.Trim() ?? string.Empty;
        normalized.ManagedValidationReceiptPath = normalized.ManagedValidationReceiptPath?.Trim() ?? string.Empty;
        normalized.ManagedControlPipeName = IsValidPipeName(normalized.ManagedControlPipeName)
            ? normalized.ManagedControlPipeName.Trim()
            : NsrlServerProtocol.DefaultControlPipeName;
        if (TryResolveEndpoint(normalized, out var endpoint, out _))
        {
            normalized.Endpoint = endpoint.AbsoluteUri;
        }

        return normalized;
    }

    private static bool IsValidPipeName(string? value)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= 128 &&
           value.All(character => char.IsLetterOrDigit(character) || character is '.' or '_' or '-');

    public static bool TryResolveEndpoint(
        KnownFileLookupSettings settings,
        out Uri endpoint,
        out string error)
    {
        endpoint = null!;
        error = string.Empty;
        if (!Uri.TryCreate(settings.Endpoint?.Trim(), UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            error = "NSRL endpoint must be an absolute HTTP or HTTPS URL.";
            return false;
        }

        if (!string.IsNullOrEmpty(parsed.UserInfo) ||
            !string.IsNullOrEmpty(parsed.Query) ||
            !string.IsNullOrEmpty(parsed.Fragment))
        {
            error = "NSRL endpoint cannot contain credentials, a query, or a fragment.";
            return false;
        }

        var builder = new UriBuilder(parsed)
        {
            Path = parsed.AbsolutePath.EndsWith("/", StringComparison.Ordinal)
                ? parsed.AbsolutePath
                : $"{parsed.AbsolutePath}/",
            Query = string.Empty,
            Fragment = string.Empty
        };
        endpoint = builder.Uri;
        return true;
    }

    public static bool IsLoopback(Uri endpoint)
    {
        if (string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return System.Net.IPAddress.TryParse(endpoint.Host, out var address) &&
               System.Net.IPAddress.IsLoopback(address);
    }
}
