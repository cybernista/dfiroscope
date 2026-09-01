using System.Text.Json;

namespace ProcInsider.Services;

public enum PortablePackageApplicationRole
{
    Unknown = 0,
    Viewer = 1,
    Agent = 2
}

public sealed record PortablePackageLocation
{
    public string PackageRoot { get; init; } = string.Empty;
    public string ApplicationDirectory { get; init; } = string.Empty;
    public PortablePackageApplicationRole ApplicationRole { get; init; }
    public string CapturesDirectory { get; init; } = string.Empty;
    public string MarkerPath { get; init; } = string.Empty;
}

public sealed class PortablePackageLocationException : IOException
{
    public PortablePackageLocationException(string message) : base(message)
    {
    }

    public PortablePackageLocationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Resolves the explicit package-owned storage contract shared by the portable
/// Viewer and Agent. A directory name or current working directory is never
/// sufficient to opt a process into portable capture storage.
/// </summary>
public static class PortablePackageLocationService
{
    public const int CurrentSchemaVersion = 1;
    public const string PackageKind = "DFIRoscope.Live.Portable";
    public const string MarkerFileName = "DFIRoscope-Portable.json";
    public const string ViewerDirectoryName = "Viewer";
    public const string AgentDirectoryName = "Agent";
    public const string CapturesDirectoryName = "Captures";
    public const string ViewerExecutableName = "DFIRoscope.Live.exe";
    public const string AgentExecutableName = "DFIRoscope.Agent.exe";

    private const int MaximumMarkerBytes = 16 * 1024;

    private static readonly string[] RequiredProperties =
    [
        "schemaVersion",
        "packageKind",
        "viewerDirectory",
        "agentDirectory",
        "capturesDirectory"
    ];

    public static PortablePackageLocation? TryResolve(string applicationBaseDirectory)
    {
        if (string.IsNullOrWhiteSpace(applicationBaseDirectory))
        {
            throw new ArgumentException("An application base directory is required.", nameof(applicationBaseDirectory));
        }

        var applicationDirectory = NormalizeDirectory(applicationBaseDirectory);
        var packageRoot = Directory.GetParent(applicationDirectory)?.FullName;
        if (string.IsNullOrWhiteSpace(packageRoot))
        {
            return null;
        }

        packageRoot = NormalizeDirectory(packageRoot);
        var markerPath = Path.Combine(packageRoot, MarkerFileName);
        var markerAttributes = TryGetAttributes(markerPath);
        if (markerAttributes == null)
        {
            return null;
        }

        ValidatePathAttributes(markerPath, markerAttributes.Value, expectDirectory: false);
        ValidateExistingDirectory(packageRoot, "portable package root");
        ValidateExistingDirectory(applicationDirectory, "portable application directory");

        var marker = ReadMarker(markerPath);
        var viewerDirectory = Path.Combine(packageRoot, marker.ViewerDirectory);
        var agentDirectory = Path.Combine(packageRoot, marker.AgentDirectory);
        var capturesDirectory = Path.Combine(packageRoot, marker.CapturesDirectory);
        ValidateContainedDirectChild(packageRoot, viewerDirectory, ViewerDirectoryName);
        ValidateContainedDirectChild(packageRoot, agentDirectory, AgentDirectoryName);
        ValidateContainedDirectChild(packageRoot, capturesDirectory, CapturesDirectoryName);
        ValidateExistingDirectory(viewerDirectory, "portable Viewer directory");
        ValidateExistingDirectory(agentDirectory, "portable Agent directory");
        ValidateExistingFile(Path.Combine(viewerDirectory, ViewerExecutableName), "portable Viewer primary executable");
        ValidateExistingFile(Path.Combine(agentDirectory, AgentExecutableName), "portable Agent primary executable");

        var role = PathsEqual(applicationDirectory, viewerDirectory)
            ? PortablePackageApplicationRole.Viewer
            : PathsEqual(applicationDirectory, agentDirectory)
                ? PortablePackageApplicationRole.Agent
                : PortablePackageApplicationRole.Unknown;
        if (role == PortablePackageApplicationRole.Unknown)
        {
            throw new PortablePackageLocationException(
                $"The portable marker '{markerPath}' does not authorize application directory '{applicationDirectory}'.");
        }

        ValidateCaptureDirectoryState(capturesDirectory);
        return new PortablePackageLocation
        {
            PackageRoot = packageRoot,
            ApplicationDirectory = applicationDirectory,
            ApplicationRole = role,
            CapturesDirectory = capturesDirectory,
            MarkerPath = markerPath
        };
    }

    internal static void ValidateCaptureDirectory(PortablePackageLocation location)
    {
        ArgumentNullException.ThrowIfNull(location);
        var current = TryResolve(location.ApplicationDirectory) ??
            throw new PortablePackageLocationException(
                $"The portable package marker disappeared before capture creation: {location.MarkerPath}");
        if (!PathsEqual(current.PackageRoot, location.PackageRoot) ||
            !PathsEqual(current.CapturesDirectory, location.CapturesDirectory) ||
            current.ApplicationRole != location.ApplicationRole)
        {
            throw new PortablePackageLocationException(
                "The portable package location changed while capture creation was being validated.");
        }
    }

    private static PortablePackageMarker ReadMarker(string markerPath)
    {
        try
        {
            var markerInfo = new FileInfo(markerPath);
            if (markerInfo.Length is <= 0 or > MaximumMarkerBytes)
            {
                throw new PortablePackageLocationException(
                    $"The portable package marker must contain 1..{MaximumMarkerBytes} bytes: {markerPath}");
            }

            var bytes = File.ReadAllBytes(markerPath);
            if (bytes.Length is <= 0 or > MaximumMarkerBytes)
            {
                throw new PortablePackageLocationException(
                    $"The portable package marker changed outside the 1..{MaximumMarkerBytes} byte limit while it was read: {markerPath}");
            }

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new PortablePackageLocationException("The portable package marker must be a JSON object.");
            }

            var observedProperties = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!observedProperties.Add(property.Name))
                {
                    throw new PortablePackageLocationException(
                        $"The portable package marker repeats property '{property.Name}'.");
                }

                if (!RequiredProperties.Contains(property.Name, StringComparer.Ordinal))
                {
                    throw new PortablePackageLocationException(
                        $"The portable package marker contains unsupported property '{property.Name}'.");
                }
            }

            if (observedProperties.Count != RequiredProperties.Length ||
                RequiredProperties.Any(property => !observedProperties.Contains(property)))
            {
                throw new PortablePackageLocationException(
                    "The portable package marker is missing one or more required properties.");
            }

            var root = document.RootElement;
            var schemaVersion = ReadInt32(root, "schemaVersion");
            var packageKind = ReadString(root, "packageKind");
            var viewerDirectory = ReadString(root, "viewerDirectory");
            var agentDirectory = ReadString(root, "agentDirectory");
            var capturesDirectory = ReadString(root, "capturesDirectory");
            if (schemaVersion != CurrentSchemaVersion ||
                !string.Equals(packageKind, PackageKind, StringComparison.Ordinal) ||
                !string.Equals(viewerDirectory, ViewerDirectoryName, StringComparison.Ordinal) ||
                !string.Equals(agentDirectory, AgentDirectoryName, StringComparison.Ordinal) ||
                !string.Equals(capturesDirectory, CapturesDirectoryName, StringComparison.Ordinal))
            {
                throw new PortablePackageLocationException(
                    "The portable package marker does not match the supported schema and fixed directory contract.");
            }

            return new PortablePackageMarker(
                schemaVersion,
                packageKind,
                viewerDirectory,
                agentDirectory,
                capturesDirectory);
        }
        catch (PortablePackageLocationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            throw new PortablePackageLocationException(
                $"The portable package marker could not be read safely: {markerPath}",
                ex);
        }
    }

    private static int ReadInt32(JsonElement root, string propertyName)
    {
        var value = root.GetProperty(propertyName);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result))
        {
            throw new PortablePackageLocationException(
                $"Portable package property '{propertyName}' must be an integer.");
        }

        return result;
    }

    private static string ReadString(JsonElement root, string propertyName)
    {
        var value = root.GetProperty(propertyName);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new PortablePackageLocationException(
                $"Portable package property '{propertyName}' must be a non-empty string.");
        }

        return value.GetString()!;
    }

    private static void ValidateCaptureDirectoryState(string capturesDirectory)
    {
        var attributes = TryGetAttributes(capturesDirectory);
        if (attributes != null)
        {
            ValidatePathAttributes(capturesDirectory, attributes.Value, expectDirectory: true);
        }
    }

    private static void ValidateExistingDirectory(string path, string description)
    {
        var attributes = TryGetAttributes(path) ??
            throw new PortablePackageLocationException($"The {description} is missing: {path}");
        ValidatePathAttributes(path, attributes, expectDirectory: true);
    }

    private static void ValidateExistingFile(string path, string description)
    {
        var attributes = TryGetAttributes(path) ??
            throw new PortablePackageLocationException($"The {description} is missing: {path}");
        ValidatePathAttributes(path, attributes, expectDirectory: false);
    }

    private static FileAttributes? TryGetAttributes(string path)
    {
        try
        {
            return File.GetAttributes(path);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new PortablePackageLocationException(
                $"Portable package path metadata could not be read safely: {path}",
                ex);
        }
    }

    private static void ValidatePathAttributes(string path, FileAttributes attributes, bool expectDirectory)
    {
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new PortablePackageLocationException(
                $"Portable package paths cannot be reparse points: {path}");
        }

        var isDirectory = (attributes & FileAttributes.Directory) != 0;
        if (isDirectory != expectDirectory)
        {
            throw new PortablePackageLocationException(
                expectDirectory
                    ? $"The portable package requires a directory at: {path}"
                    : $"The portable package requires a regular file at: {path}");
        }
    }

    private static void ValidateContainedDirectChild(string packageRoot, string candidate, string expectedName)
    {
        var relative = Path.GetRelativePath(packageRoot, candidate);
        if (!string.Equals(relative, expectedName, StringComparison.Ordinal) ||
            Path.IsPathRooted(relative) ||
            relative.Contains(Path.DirectorySeparatorChar) ||
            relative.Contains(Path.AltDirectorySeparatorChar))
        {
            throw new PortablePackageLocationException(
                $"Portable package directory '{expectedName}' must be an immediate child of the package root.");
        }
    }

    private static string NormalizeDirectory(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static bool PathsEqual(string left, string right) =>
        string.Equals(NormalizeDirectory(left), NormalizeDirectory(right), StringComparison.OrdinalIgnoreCase);

    private sealed record PortablePackageMarker(
        int SchemaVersion,
        string PackageKind,
        string ViewerDirectory,
        string AgentDirectory,
        string CapturesDirectory);
}
