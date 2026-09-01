using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class FilesystemArtifactLoaderService
{
    private const int MaxRawSampleBytes = 4096;
    private const int MaxPrefetchStringBytes = 512 * 1024;

    public async Task<IReadOnlyList<FilesystemArtifactRecord>> LoadAsync(
        FilesystemArtifactImportOptions options,
        Guid? jobId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Path))
        {
            throw new ArgumentException("An artifact import path is required.", nameof(options));
        }

        var records = new List<FilesystemArtifactRecord>();
        foreach (var path in EnumerateCandidatePaths(options, records, jobId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            records.Add(await LoadFileAsync(path, options, jobId, cancellationToken).ConfigureAwait(false));
            if (records.Count >= Math.Clamp(options.MaxFiles, 1, 100000))
            {
                break;
            }
        }

        return records;
    }

    private static IEnumerable<string> EnumerateCandidatePaths(
        FilesystemArtifactImportOptions options,
        List<FilesystemArtifactRecord> records,
        Guid? jobId)
    {
        if (File.Exists(options.Path))
        {
            yield return options.Path;
            yield break;
        }

        if (!Directory.Exists(options.Path))
        {
            records.Add(CreateFailure(options.Path, jobId, FilesystemArtifactKind.Unknown, "The selected artifact path does not exist."));
            yield break;
        }

        var pending = new Stack<string>();
        pending.Push(options.Path);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directory).ToList();
            }
            catch (Exception ex) when (IsRecoverableFileError(ex))
            {
                records.Add(CreateFailure(directory, jobId, FilesystemArtifactKind.Unknown, $"Could not enumerate directory: {ex.Message}"));
                continue;
            }

            foreach (var file in files)
            {
                var kind = DetectKind(file);
                if (IsAllowed(kind, options))
                {
                    yield return file;
                }
            }

            if (!options.Recurse)
            {
                continue;
            }

            IEnumerable<string> children;
            try
            {
                children = Directory.EnumerateDirectories(directory).ToList();
            }
            catch (Exception ex) when (IsRecoverableFileError(ex))
            {
                records.Add(CreateFailure(directory, jobId, FilesystemArtifactKind.Unknown, $"Could not enumerate child directories: {ex.Message}"));
                continue;
            }

            foreach (var child in children)
            {
                pending.Push(child);
            }
        }
    }

    private static async Task<FilesystemArtifactRecord> LoadFileAsync(
        string path,
        FilesystemArtifactImportOptions options,
        Guid? jobId,
        CancellationToken cancellationToken)
    {
        var kind = DetectKind(path);
        if (!IsAllowed(kind, options))
        {
            return CreateFailure(path, jobId, kind, "The selected file is not a supported NTFS or Prefetch artifact.");
        }

        try
        {
            var info = new FileInfo(path);
            var hash = await ComputeSha256Async(path, cancellationToken).ConfigureAwait(false);
            var rawSample = await ReadRawSampleAsync(path, cancellationToken).ConfigureAwait(false);
            var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ArtifactKind"] = kind.ToString(),
                ["SourcePath"] = path,
                ["FileName"] = info.Name,
                ["FileSizeBytes"] = info.Exists ? info.Length.ToString() : "0"
            };

            var record = new FilesystemArtifactRecord
            {
                ArtifactId = CreateArtifactId(kind, path, hash),
                JobId = jobId,
                Kind = kind,
                Status = FilesystemArtifactStatus.Imported,
                TimestampUtc = DateTime.UtcNow,
                Name = info.Name,
                SourcePath = path,
                FileSizeBytes = info.Exists ? info.Length : 0,
                CreatedUtc = info.Exists ? info.CreationTimeUtc : null,
                LastModifiedUtc = info.Exists ? info.LastWriteTimeUtc : null,
                Sha256Hash = hash,
                RawPayloadHash = hash,
                RawText = rawSample,
                Source = "AgentArtifactImport"
            };

            if (kind == FilesystemArtifactKind.Prefetch)
            {
                PopulatePrefetch(path, record, properties);
            }
            else
            {
                PopulateNtfs(record, properties);
            }

            record.Properties = properties;
            record.Summary = string.IsNullOrWhiteSpace(record.Summary)
                ? $"{kind} artifact imported from {path}"
                : record.Summary;
            return record;
        }
        catch (Exception ex) when (IsRecoverableFileError(ex))
        {
            return CreateFailure(path, jobId, kind, ex.Message);
        }
    }

    private static void PopulateNtfs(FilesystemArtifactRecord record, Dictionary<string, string> properties)
    {
        properties["Parser"] = "NTFS metadata loader";
        properties["RawIdentity"] = "File path, timestamps, size, SHA256, and bounded header sample";
        record.Summary = record.Kind switch
        {
            FilesystemArtifactKind.NtfsMft => "NTFS $MFT metadata/header sample staged.",
            FilesystemArtifactKind.NtfsUsnJournal => "NTFS USN journal metadata/header sample staged.",
            FilesystemArtifactKind.NtfsLogFile => "NTFS $LogFile metadata/header sample staged.",
            _ => "Filesystem metadata/header sample staged."
        };
    }

    private static void PopulatePrefetch(
        string path,
        FilesystemArtifactRecord record,
        Dictionary<string, string> properties)
    {
        properties["Parser"] = "Prefetch header loader";
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length < 84)
        {
            record.Status = FilesystemArtifactStatus.Failed;
            record.ErrorMessage = "Prefetch file is too small to contain a valid header.";
            record.Summary = "Prefetch parse failed: file is too small.";
            return;
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
        var signature = Encoding.ASCII.GetString(bytes, 4, Math.Min(4, bytes.Length - 4));
        properties["PrefetchVersion"] = version.ToString();
        properties["Signature"] = signature;

        if (!string.Equals(signature, "SCCA", StringComparison.Ordinal))
        {
            record.Status = FilesystemArtifactStatus.Failed;
            record.ErrorMessage = "Prefetch signature was not SCCA.";
            record.Summary = "Prefetch parse failed: invalid signature.";
            return;
        }

        var executableName = ReadUtf16NullTerminated(bytes, 16, Math.Min(60, bytes.Length - 16));
        record.ProcessName = executableName;
        properties["ExecutableName"] = executableName;

        var runCountOffset = version switch
        {
            17 => 0x90,
            23 => 0x98,
            26 or 30 or 31 => 0xD0,
            _ => 0
        };
        if (runCountOffset > 0 && runCountOffset + 4 <= bytes.Length)
        {
            record.RunCount = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(runCountOffset, 4));
            properties["RunCount"] = record.RunCount.ToString();
        }

        var lastRun = ReadFileTime(bytes, 0x80);
        if (lastRun.HasValue)
        {
            record.LastRunUtc = lastRun;
            properties["LastRunUtc"] = lastRun.Value.ToString("O");
            record.TimestampUtc = lastRun.Value;
        }

        var referencedPaths = ExtractUtf16PathStrings(bytes).Take(20).ToList();
        if (referencedPaths.Count > 0)
        {
            properties["ReferencedPathCountSample"] = referencedPaths.Count.ToString();
            properties["ReferencedPathsJson"] = JsonSerializer.Serialize(referencedPaths);
        }

        record.Summary = string.IsNullOrWhiteSpace(executableName)
            ? $"Prefetch artifact parsed ({record.RunCount} run(s))."
            : $"Prefetch for {executableName} ({record.RunCount} run(s)).";
    }

    private static DateTime? ReadFileTime(byte[] bytes, int offset)
    {
        if (offset + 8 > bytes.Length)
        {
            return null;
        }

        var value = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(offset, 8));
        if (value <= 0)
        {
            return null;
        }

        try
        {
            var utc = DateTime.FromFileTimeUtc(value);
            return utc.Year is >= 1995 and <= 3000 ? utc : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static IEnumerable<string> ExtractUtf16PathStrings(byte[] bytes)
    {
        var length = Math.Min(bytes.Length, MaxPrefetchStringBytes);
        var text = Encoding.Unicode.GetString(bytes, 0, length);
        var current = new StringBuilder();
        foreach (var ch in text)
        {
            if (!char.IsControl(ch))
            {
                current.Append(ch);
                continue;
            }

            foreach (var value in FlushCandidate(current))
            {
                yield return value;
            }
        }

        foreach (var value in FlushCandidate(current))
        {
            yield return value;
        }
    }

    private static IEnumerable<string> FlushCandidate(StringBuilder current)
    {
        if (current.Length < 6)
        {
            current.Clear();
            yield break;
        }

        var value = current.ToString();
        current.Clear();
        if ((value.Contains(@":\", StringComparison.Ordinal) ||
             value.StartsWith(@"\DEVICE\", StringComparison.OrdinalIgnoreCase)) &&
            value.Length <= 512)
        {
            yield return value;
        }
    }

    private static string ReadUtf16NullTerminated(byte[] bytes, int offset, int maxBytes)
    {
        if (offset >= bytes.Length || maxBytes <= 0)
        {
            return string.Empty;
        }

        var text = Encoding.Unicode.GetString(bytes, offset, maxBytes);
        var nullIndex = text.IndexOf('\0', StringComparison.Ordinal);
        return (nullIndex >= 0 ? text[..nullIndex] : text).Trim();
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 128, useAsync: true);
        using var sha256 = SHA256.Create();
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task<string> ReadRawSampleAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 16, useAsync: true);
        var buffer = new byte[Math.Min(MaxRawSampleBytes, (int)Math.Min(stream.Length, MaxRawSampleBytes))];
        var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(buffer.AsSpan(0, read));
    }

    private static FilesystemArtifactKind DetectKind(string path)
    {
        var fileName = Path.GetFileName(path);
        if (fileName.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
        {
            return FilesystemArtifactKind.Prefetch;
        }

        if (string.Equals(fileName, "$MFT", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fileName, "MFT", StringComparison.OrdinalIgnoreCase))
        {
            return FilesystemArtifactKind.NtfsMft;
        }

        if (string.Equals(fileName, "$LogFile", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fileName, "LogFile", StringComparison.OrdinalIgnoreCase))
        {
            return FilesystemArtifactKind.NtfsLogFile;
        }

        return fileName.Contains("UsnJrnl", StringComparison.OrdinalIgnoreCase) ||
               fileName.Contains("$J", StringComparison.OrdinalIgnoreCase)
            ? FilesystemArtifactKind.NtfsUsnJournal
            : FilesystemArtifactKind.FileMetadata;
    }

    private static bool IsAllowed(FilesystemArtifactKind kind, FilesystemArtifactImportOptions options)
    {
        return kind switch
        {
            FilesystemArtifactKind.Prefetch => options.IncludePrefetch,
            FilesystemArtifactKind.NtfsMft or FilesystemArtifactKind.NtfsUsnJournal or FilesystemArtifactKind.NtfsLogFile => options.IncludeNtfs,
            _ => false
        };
    }

    private static FilesystemArtifactRecord CreateFailure(
        string path,
        Guid? jobId,
        FilesystemArtifactKind kind,
        string error)
    {
        return new FilesystemArtifactRecord
        {
            ArtifactId = CreateArtifactId(kind, path, error),
            JobId = jobId,
            Kind = kind,
            Status = FilesystemArtifactStatus.Failed,
            TimestampUtc = DateTime.UtcNow,
            Name = Path.GetFileName(path),
            SourcePath = path,
            Summary = $"Artifact import failed for {path}",
            ErrorMessage = error,
            Source = "AgentArtifactImport",
            Properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["SourcePath"] = path,
                ["Error"] = error
            }
        };
    }

    private static string CreateArtifactId(FilesystemArtifactKind kind, string path, string identity)
    {
        var input = $"{kind}|{Path.GetFullPath(path)}|{identity}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant()[..32];
    }

    private static bool IsRecoverableFileError(Exception ex)
    {
        return ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException or PathTooLongException;
    }
}

public sealed class FilesystemArtifactImportOptions
{
    public string Path { get; init; } = string.Empty;
    public bool Recurse { get; init; } = true;
    public bool IncludeNtfs { get; init; } = true;
    public bool IncludePrefetch { get; init; } = true;
    public int MaxFiles { get; init; } = 10000;
}
