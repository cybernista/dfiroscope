using System.Text.RegularExpressions;

namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlCatalogPathService
{
    public const string ActivePointerFileName = "active-generation.json";
    public const string PreviousPointerFileName = "previous-generation.json";
    public const string ManifestFileName = "generation-manifest.json";

    private static readonly Regex SafeNameRegex = new(
        "^[a-z0-9][a-z0-9._-]{0,127}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public NsrlCatalogPathService(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("An explicit NSRL reference-data root is required.", nameof(root));
        }

        Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var pathRoot = Path.GetPathRoot(Root);
        if (pathRoot is not null &&
            string.Equals(Root, Path.TrimEndingDirectorySeparator(pathRoot), StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A drive root cannot be used as the NSRL reference-data root.", nameof(root));
        }
    }

    public string Root { get; }

    public string DownloadsRoot => Path.Combine(Root, "downloads");

    public string StagingRoot => Path.Combine(Root, ".staging");

    public string GenerationsRoot => Path.Combine(Root, "generations");

    public string ActivePointerPath => Path.Combine(Root, ActivePointerFileName);

    public string PreviousPointerPath => Path.Combine(Root, PreviousPointerFileName);

    public string GetPartialArchivePath(string releaseKey)
        => Contain(DownloadsRoot, SafeName(releaseKey) + ".zip.partial");

    public string GetResumeMetadataPath(string releaseKey)
        => Contain(DownloadsRoot, SafeName(releaseKey) + ".resume.json");

    public string GetStagingGenerationRoot(string generationId)
        => Contain(StagingRoot, SafeName(generationId));

    public string GetGenerationRoot(string generationId)
        => Contain(GenerationsRoot, SafeName(generationId));

    public string GetGenerationManifestPath(string generationId)
        => Path.Combine(GetGenerationRoot(generationId), ManifestFileName);

    public void EnsureWritableLayout()
    {
        EnsureNoExistingReparsePoint(Root);
        Directory.CreateDirectory(Root);
        EnsureDirectory(Root);
        EnsureDirectory(DownloadsRoot);
        EnsureDirectory(StagingRoot);
        EnsureDirectory(GenerationsRoot);
    }

    public void AssertContained(string candidate)
    {
        _ = Contain(Root, Path.GetRelativePath(Root, Path.GetFullPath(candidate)));
    }

    public static string SafeName(string value)
    {
        var normalized = value.Trim().ToLowerInvariant();
        if (!SafeNameRegex.IsMatch(normalized))
        {
            throw new InvalidDataException("The NSRL catalog identifier contains unsupported characters.");
        }

        return normalized;
    }

    private static string Contain(string root, string relative)
    {
        if (Path.IsPathRooted(relative))
        {
            throw new InvalidDataException("An NSRL catalog relative path cannot be rooted.");
        }

        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var candidate = Path.GetFullPath(Path.Combine(fullRoot, relative));
        var prefix = fullRoot + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The NSRL catalog path escapes its explicit reference-data root.");
        }

        return candidate;
    }

    private static void EnsureDirectory(string path)
    {
        EnsureNoExistingReparsePoint(path);
        Directory.CreateDirectory(path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("The NSRL catalog path cannot traverse a reparse point.");
        }
    }

    private static void EnsureNoExistingReparsePoint(string path)
    {
        var cursor = new DirectoryInfo(Path.GetFullPath(path));
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
            var directory = existing.Pop();
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("The NSRL catalog root cannot traverse a reparse point.");
            }
        }
    }
}
