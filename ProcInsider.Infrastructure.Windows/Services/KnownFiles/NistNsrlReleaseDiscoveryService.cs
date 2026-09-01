using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed partial class NistNsrlReleaseDiscoveryService : INsrlReleaseDiscoveryService, IDisposable
{
    public static readonly Uri CurrentReleasePage = new(
        "https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/nsrl-download-0");

    private const int MaxReleasePageBytes = 2 * 1024 * 1024;
    private const int MaxSupportDocumentBytes = 256 * 1024;
    private readonly NistNsrlHttpClient _http;
    private readonly bool _disposeHttp;

    public NistNsrlReleaseDiscoveryService()
        : this(NistNsrlHttpClient.CreateDefault(), disposeHttp: true)
    {
    }

    public NistNsrlReleaseDiscoveryService(NistNsrlHttpClient http, bool disposeHttp = false)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _disposeHttp = disposeHttp;
    }

    public async Task<NsrlReleaseDescriptor> DiscoverLatestModernMinimalFullAsync(
        CancellationToken cancellationToken = default)
    {
        var page = await _http.GetBoundedTextAsync(
            CurrentReleasePage,
            NistNsrlRemoteResourceKind.ReleasePage,
            MaxReleasePageBytes,
            cancellationToken).ConfigureAwait(false);

        var row = FindLatestFullPublicationRow(page);
        var releaseId = ExtractSingle(row, ReleaseIdRegex(), "full RDS release identifier");
        var anchors = ParseAnchors(row);
        var archiveUri = SelectSingleUri(
            anchors,
            uri => uri.AbsolutePath.EndsWith($"/RDS_{releaseId}_modern_minimal.zip", StringComparison.OrdinalIgnoreCase),
            "Modern Minimal full archive");
        var readmeUri = SelectSingleUri(
            anchors,
            uri => uri.AbsolutePath.EndsWith("/README.txt", StringComparison.OrdinalIgnoreCase),
            "release README");
        var versionUri = SelectSingleUri(
            anchors,
            uri => uri.AbsolutePath.EndsWith("/version.txt", StringComparison.OrdinalIgnoreCase),
            "release version document");
        var databaseHashUri = SelectSingleUri(
            anchors,
            uri => uri.AbsolutePath.EndsWith("/dbhashes.txt", StringComparison.OrdinalIgnoreCase),
            "database hash document");

        var archiveHashUri = new Uri(archiveUri.AbsoluteUri + ".sha", UriKind.Absolute);
        var archiveFileName = Path.GetFileName(archiveUri.AbsolutePath);
        var databaseFileName = Path.GetFileNameWithoutExtension(archiveFileName) + ".db";
        var documents = await Task.WhenAll(
            _http.GetBoundedTextAsync(readmeUri, NistNsrlRemoteResourceKind.Distribution, MaxSupportDocumentBytes, cancellationToken),
            _http.GetBoundedTextAsync(versionUri, NistNsrlRemoteResourceKind.Distribution, MaxSupportDocumentBytes, cancellationToken),
            _http.GetBoundedTextAsync(databaseHashUri, NistNsrlRemoteResourceKind.Distribution, MaxSupportDocumentBytes, cancellationToken),
            _http.GetBoundedTextAsync(archiveHashUri, NistNsrlRemoteResourceKind.Distribution, MaxSupportDocumentBytes, cancellationToken)).ConfigureAwait(false);

        var readme = documents[0];
        var versionDocument = documents[1];
        var databaseHashes = documents[2];
        var archiveHashes = documents[3];
        RequireExactDocumentReference(readme, archiveUri);
        RequireExactDocumentReference(readme, archiveHashUri);
        RequireVersionIdentity(versionDocument, releaseId);

        var archiveDigest = ParseExpectedDigest(archiveHashes, archiveFileName, "archive", isSqliteDbHash: false);
        var databaseDigest = ParseExpectedDigest(databaseHashes, databaseFileName, "database", isSqliteDbHash: true);
        var archiveSize = ParseArchiveSize(readme, archiveUri);
        var estimatedExtractedSize = checked(Math.Max(archiveSize, archiveSize * 8));
        var releaseDate = ParseReleaseDate(versionDocument, releaseId);

        return new NsrlReleaseDescriptor
        {
            ReleaseId = releaseId,
            ReleaseDateUtc = releaseDate,
            DataSet = "Modern",
            Profile = "Minimal",
            PublicationKind = "FullSql",
            ReleasePageUri = CurrentReleasePage,
            ReadmeUri = readmeUri,
            VersionDocumentUri = versionUri,
            DatabaseHashDocumentUri = databaseHashUri,
            ArchiveUri = archiveUri,
            ArchiveHashUri = archiveHashUri,
            ArchiveFileName = archiveFileName,
            DatabaseFileName = databaseFileName,
            ArchiveSizeBytes = archiveSize,
            EstimatedExtractedSizeBytes = estimatedExtractedSize,
            ExtractedSizeEstimateSource = "Conservative 8x archive-size preflight; the ZIP entry size is enforced before extraction.",
            ExpectedArchiveDigest = archiveDigest,
            ExpectedDatabaseDigest = databaseDigest
        };
    }

    public void Dispose()
    {
        if (_disposeHttp)
        {
            _http.Dispose();
        }
    }

    private static string FindLatestFullPublicationRow(string html)
    {
        foreach (Match match in TableRowRegex().Matches(html))
        {
            var text = StripMarkup(match.Value);
            if (text.Contains("Full", StringComparison.OrdinalIgnoreCase) &&
                text.Contains("SQL Downloads", StringComparison.OrdinalIgnoreCase) &&
                !text.Contains("Delta SQL Downloads", StringComparison.OrdinalIgnoreCase) &&
                text.Contains("minimal", StringComparison.OrdinalIgnoreCase))
            {
                return match.Value;
            }
        }

        throw new InvalidDataException("The NIST NSRL page no longer exposes one supported full Modern Minimal RDSv3 table row.");
    }

    private static IReadOnlyList<Uri> ParseAnchors(string html)
    {
        var links = new List<Uri>();
        foreach (Match match in AnchorRegex().Matches(html))
        {
            var value = WebUtility.HtmlDecode(match.Groups["href"].Value).Trim();
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                continue;
            }

            NistNsrlHttpClient.ValidateUri(uri, NistNsrlRemoteResourceKind.Distribution);
            links.Add(uri);
        }

        return links;
    }

    private static Uri SelectSingleUri(
        IEnumerable<Uri> links,
        Func<Uri, bool> predicate,
        string description)
    {
        var matches = links.Where(predicate).DistinctBy(uri => uri.AbsoluteUri, StringComparer.Ordinal).ToArray();
        return matches.Length switch
        {
            1 => matches[0],
            0 => throw new InvalidDataException($"The NIST NSRL page is missing the {description}."),
            _ => throw new InvalidDataException($"The NIST NSRL page contains an ambiguous {description}.")
        };
    }

    private static string ExtractSingle(string value, Regex regex, string description)
    {
        var matches = regex.Matches(value)
            .Select(match => match.Groups["value"].Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return matches.Length switch
        {
            1 => matches[0],
            0 => throw new InvalidDataException($"The NIST NSRL page is missing the {description}."),
            _ => throw new InvalidDataException($"The NIST NSRL page contains an ambiguous {description}.")
        };
    }

    private static void RequireExactDocumentReference(string document, Uri expectedUri)
    {
        if (!document.Contains(expectedUri.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The NIST NSRL README does not bind the selected archive to its expected support document chain.");
        }
    }

    private static void RequireVersionIdentity(string document, string releaseId)
    {
        if (!document.Contains($"RDS Version {releaseId}", StringComparison.Ordinal) ||
            !document.Contains($"{releaseId} modern minimal", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The NIST version document does not identify the selected Modern Minimal release.");
        }
    }

    private static NsrlExpectedDigest ParseExpectedDigest(
        string document,
        string exactFileName,
        string description,
        bool isSqliteDbHash)
    {
        var candidates = DigestLineRegex().Matches(document)
            .Where(match => string.Equals(match.Groups["file"].Value, exactFileName, StringComparison.Ordinal))
            .Select(match => match.Groups["digest"].Value.ToUpperInvariant())
            .ToList();
        if (!isSqliteDbHash)
        {
            candidates.AddRange(ArchiveSha1DigestLineRegex().Matches(document)
                .Where(match => string.Equals(match.Groups["file"].Value, exactFileName, StringComparison.Ordinal))
                .Select(match => match.Groups["digest"].Value.ToUpperInvariant()));
            candidates.AddRange(ArchiveSha256DigestLineRegex().Matches(document)
                .Where(match => string.Equals(match.Groups["file"].Value, exactFileName, StringComparison.Ordinal))
                .Select(match => match.Groups["digest"].Value.ToUpperInvariant()));
        }

        var matches = candidates
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (matches.Length == 0)
        {
            throw new InvalidDataException($"The NIST {description} hash document is missing the exact expected digest.");
        }

        if (matches.Length != 1)
        {
            throw new InvalidDataException($"The NIST {description} hash document contains ambiguous expected digests.");
        }

        if (isSqliteDbHash && matches[0].Length != 40)
        {
            throw new InvalidDataException("The NIST database hash document does not contain a SQLite dbhash SHA-1 value.");
        }

        var algorithm = isSqliteDbHash
            ? NsrlDigestAlgorithm.SqliteDbHashSha1
            : matches[0].Length == 40
                ? NsrlDigestAlgorithm.Sha1
                : NsrlDigestAlgorithm.Sha256;
        return new NsrlExpectedDigest(algorithm, matches[0]);
    }

    private static long ParseArchiveSize(string readme, Uri archiveUri)
    {
        var fileName = Regex.Escape(Path.GetFileName(archiveUri.AbsolutePath));
        var match = Regex.Match(
            readme,
            $@"(?im)^https://[^\r\n\s]+/{fileName}\s+(?<value>\d+(?:\.\d+)?)\s*(?<unit>[KMGT])B?\s*$",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
        if (!match.Success ||
            !decimal.TryParse(match.Groups["value"].Value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var value))
        {
            throw new InvalidDataException("The NIST NSRL README is missing the selected archive size.");
        }

        var multiplier = match.Groups["unit"].Value.ToUpperInvariant() switch
        {
            "K" => 1_000L,
            "M" => 1_000_000L,
            "G" => 1_000_000_000L,
            "T" => 1_000_000_000_000L,
            _ => throw new InvalidDataException("The NIST NSRL README uses an unsupported archive-size unit.")
        };
        return checked((long)(value * multiplier));
    }

    private static DateTime ParseReleaseDate(string document, string releaseId)
    {
        var match = Regex.Match(
            document,
            $@"RDS\s+Version\s+{Regex.Escape(releaseId)}\s+-\s+(?<month>[A-Za-z]+)\s+(?<year>\d{{4}})",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
        if (!match.Success ||
            !DateTime.TryParseExact(
                $"1 {match.Groups["month"].Value} {match.Groups["year"].Value}",
                "d MMMM yyyy",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var date))
        {
            throw new InvalidDataException("The NIST version document is missing the selected release date.");
        }

        return DateTime.SpecifyKind(date, DateTimeKind.Utc);
    }

    private static string StripMarkup(string html)
        => WebUtility.HtmlDecode(TagRegex().Replace(html, " "));

    [GeneratedRegex("<tr\\b[^>]*>.*?</tr>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex TableRowRegex();

    [GeneratedRegex("<a\\b[^>]*href\\s*=\\s*[\"'](?<href>[^\"']+)[\"'][^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex AnchorRegex();

    [GeneratedRegex("(?<value>20\\d{2}\\.\\d{2}\\.\\d+)", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex ReleaseIdRegex();

    [GeneratedRegex("(?im)(?<digest>[0-9a-f]{40}|[0-9a-f]{64})\\s+[*]?(?<file>RDS_[A-Za-z0-9._-]+\\.(?:zip|db))\\b", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex DigestLineRegex();

    [GeneratedRegex("(?im)^\\s*SHA1\\s*\\(\\s*(?<file>RDS_[A-Za-z0-9._-]+\\.zip)\\s*\\)\\s*=\\s*(?<digest>[0-9a-f]{40})\\s*$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex ArchiveSha1DigestLineRegex();

    [GeneratedRegex("(?im)^\\s*SHA256\\s*\\(\\s*(?<file>RDS_[A-Za-z0-9._-]+\\.zip)\\s*\\)\\s*=\\s*(?<digest>[0-9a-f]{64})\\s*$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex ArchiveSha256DigestLineRegex();

    [GeneratedRegex("<[^>]+>", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex TagRegex();
}
