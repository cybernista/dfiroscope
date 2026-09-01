using System.IO.Compression;

namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlArchiveSafetyException : Exception
{
    public NsrlArchiveSafetyException(string message)
        : base(message)
    {
    }
}

public sealed class NsrlArchiveLimitException : Exception
{
    public NsrlArchiveLimitException(string message)
        : base(message)
    {
    }
}

public sealed record NsrlArchiveExtractionResult(
    string DatabasePath,
    long DatabaseSizeBytes,
    int EntryCount,
    long TotalDeclaredUncompressedBytes);

public sealed class NsrlArchiveExtractor
{
    private readonly NsrlCatalogAcquisitionOptions _options;

    public NsrlArchiveExtractor(NsrlCatalogAcquisitionOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<NsrlArchiveExtractionResult> ExtractDatabaseAsync(
        string archivePath,
        string stagingRoot,
        string exactDatabaseFileName,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(exactDatabaseFileName) ||
            !string.Equals(Path.GetFileName(exactDatabaseFileName), exactDatabaseFileName, StringComparison.Ordinal))
        {
            throw new NsrlArchiveSafetyException("The expected RDSv3 database name is not one safe filename.");
        }

        if (Directory.Exists(stagingRoot))
        {
            Directory.Delete(stagingRoot, recursive: true);
        }

        Directory.CreateDirectory(stagingRoot);
        var stagingPrefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stagingRoot)) + Path.DirectorySeparatorChar;
        try
        {
            await using var archiveStream = new FileStream(
                archivePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read, leaveOpen: false);
            if (archive.Entries.Count == 0)
            {
                throw new InvalidDataException("The NIST NSRL archive is empty.");
            }

            if (archive.Entries.Count > _options.MaxArchiveEntries)
            {
                throw new NsrlArchiveLimitException("The NIST NSRL archive exceeds the entry-count limit.");
            }

            var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ZipArchiveEntry? databaseEntry = null;
            string? databaseRelativePath = null;
            long totalDeclared = 0;
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = NormalizeEntryPath(entry.FullName);
                RejectLinkOrReparseEntry(entry);
                if (!seenTargets.Add(relative))
                {
                    throw new NsrlArchiveSafetyException("The NIST NSRL archive contains duplicate extraction targets.");
                }

                totalDeclared = checked(totalDeclared + entry.Length);
                if (totalDeclared > _options.MaxExtractedBytes)
                {
                    throw new NsrlArchiveLimitException("The NIST NSRL archive exceeds the uncompressed-byte limit.");
                }

                if (entry.Length > 0)
                {
                    var ratio = entry.CompressedLength == 0
                        ? double.PositiveInfinity
                        : (double)entry.Length / entry.CompressedLength;
                    if (ratio > _options.MaxCompressionRatio)
                    {
                        throw new NsrlArchiveLimitException("The NIST NSRL archive exceeds the compression-ratio limit.");
                    }
                }

                if (string.Equals(Path.GetFileName(relative), exactDatabaseFileName, StringComparison.Ordinal))
                {
                    if (databaseEntry is not null)
                    {
                        throw new NsrlArchiveSafetyException("The NIST NSRL archive contains multiple candidate databases.");
                    }

                    databaseEntry = entry;
                    databaseRelativePath = relative;
                }
            }

            if (databaseEntry is null || databaseRelativePath is null)
            {
                throw new InvalidDataException("The NIST NSRL archive is missing the exact expected RDSv3 database.");
            }

            var destination = Path.GetFullPath(Path.Combine(stagingRoot, databaseRelativePath));
            if (!destination.StartsWith(stagingPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new NsrlArchiveSafetyException("The NIST NSRL database extraction target escaped staging.");
            }

            var parent = Path.GetDirectoryName(destination)
                ?? throw new NsrlArchiveSafetyException("The NIST NSRL database extraction target has no parent.");
            Directory.CreateDirectory(parent);
            AssertNoReparsePath(stagingRoot, parent);

            await using var source = databaseEntry.Open();
            await using var output = new FileStream(
                destination,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
            var buffer = new byte[1024 * 1024];
            long written = 0;
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                written = checked(written + read);
                if (written > databaseEntry.Length || written > _options.MaxExtractedBytes)
                {
                    throw new NsrlArchiveLimitException("The extracted RDSv3 database exceeded its declared or configured byte limit.");
                }

                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
            if (written != databaseEntry.Length)
            {
                throw new InvalidDataException("The extracted RDSv3 database length does not match the ZIP entry.");
            }

            return new NsrlArchiveExtractionResult(destination, written, archive.Entries.Count, totalDeclared);
        }
        catch
        {
            TryDeleteStaging(stagingRoot);
            throw;
        }
    }

    private static string NormalizeEntryPath(string entryName)
    {
        if (string.IsNullOrWhiteSpace(entryName) || entryName.IndexOf('\0') >= 0)
        {
            throw new NsrlArchiveSafetyException("The NIST NSRL archive contains an empty or invalid entry name.");
        }

        var normalized = entryName.Replace('\\', '/').TrimEnd('/');
        if (normalized.Length == 0 ||
            normalized.StartsWith("/", StringComparison.Ordinal) ||
            normalized.Contains(':'))
        {
            throw new NsrlArchiveSafetyException("The NIST NSRL archive contains an absolute entry path.");
        }

        var segments = normalized.Split('/');
        if (segments.Any(segment =>
                segment.Length == 0 ||
                string.Equals(segment, ".", StringComparison.Ordinal) ||
                string.Equals(segment, "..", StringComparison.Ordinal)))
        {
            throw new NsrlArchiveSafetyException("The NIST NSRL archive contains a traversal entry path.");
        }

        return string.Join(Path.DirectorySeparatorChar, segments);
    }

    private static void RejectLinkOrReparseEntry(ZipArchiveEntry entry)
    {
        var unixFileType = (entry.ExternalAttributes >> 16) & 0xF000;
        var windowsAttributes = (FileAttributes)(entry.ExternalAttributes & 0xFFFF);
        if (unixFileType == 0xA000 || (windowsAttributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NsrlArchiveSafetyException("The NIST NSRL archive contains a link or reparse-point entry.");
        }
    }

    private static void AssertNoReparsePath(string root, string candidateDirectory)
    {
        var relative = Path.GetRelativePath(root, candidateDirectory);
        var cursor = Path.GetFullPath(root);
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            cursor = Path.Combine(cursor, segment);
            if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NsrlArchiveSafetyException("The NIST NSRL extraction path traverses a reparse point.");
            }
        }
    }

    private static void TryDeleteStaging(string stagingRoot)
    {
        try
        {
            if (Directory.Exists(stagingRoot))
            {
                Directory.Delete(stagingRoot, recursive: true);
            }
        }
        catch
        {
            // The caller reports the primary failure; bounded recovery can clean this contained staging root later.
        }
    }
}
