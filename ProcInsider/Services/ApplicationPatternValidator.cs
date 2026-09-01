using System.IO;
using System.Text.RegularExpressions;
using ProcInsider.Models.ApplicationCatalog;

namespace ProcInsider.Services;

public static class ApplicationPatternValidator
{
    public const int MaximumPatternLength = 512;
    public static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(150);

    public static void Validate(ApplicationFilenameMatcher matcher, string context)
    {
        ArgumentNullException.ThrowIfNull(matcher);
        var pattern = matcher.Pattern?.Trim() ?? string.Empty;
        if (pattern.Length == 0)
        {
            throw new InvalidDataException($"{context}: filename pattern is required.");
        }

        if (pattern.Length > MaximumPatternLength)
        {
            throw new InvalidDataException($"{context}: filename pattern exceeds {MaximumPatternLength} characters.");
        }

        if (matcher.Kind == ApplicationFilenameMatchKind.Exact)
        {
            if (!string.Equals(Path.GetFileName(pattern), pattern, StringComparison.Ordinal) ||
                pattern.IndexOfAny(['/', '\\']) >= 0)
            {
                throw new InvalidDataException($"{context}: exact filename matcher must contain only a filename.");
            }

            return;
        }

        if (matcher.Kind != ApplicationFilenameMatchKind.Regex)
        {
            throw new InvalidDataException($"{context}: unknown filename matcher kind '{matcher.Kind}'.");
        }

        try
        {
            _ = new Regex(
                pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
                MatchTimeout);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException($"{context}: regex must be valid for the bounded non-backtracking matcher: {ex.Message}", ex);
        }
    }

    public static bool IsMatch(ApplicationFilenameMatcher matcher, string executableFilename)
    {
        var normalizedFilename = NormalizeFilename(executableFilename);
        if (normalizedFilename.Length == 0)
        {
            return false;
        }

        return matcher.Kind switch
        {
            ApplicationFilenameMatchKind.Exact => string.Equals(
                NormalizeFilename(matcher.Pattern),
                normalizedFilename,
                StringComparison.Ordinal),
            ApplicationFilenameMatchKind.Regex => Regex.IsMatch(
                normalizedFilename,
                matcher.Pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
                MatchTimeout),
            _ => false
        };
    }

    public static string NormalizeFilename(string value)
    {
        var filename = Path.GetFileName(value?.Trim() ?? string.Empty);
        return filename.ToLowerInvariant();
    }
}
