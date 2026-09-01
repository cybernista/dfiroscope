using System.IO;
using System.Security.Cryptography;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services;

public sealed class MemoryImageImportService
{
    private readonly InvestigationSessionPaths? _sessionPaths;

    public MemoryImageImportService(InvestigationSessionPaths? sessionPaths = null)
    {
        _sessionPaths = sessionPaths;
    }

    public async Task<MemoryImageRecord> ImportAsync(
        string imagePath,
        Guid? jobId = null,
        string displayName = "",
        string acquisitionTool = "Analyst import",
        string acquisitionToolVersion = "",
        string acquisitionCommandLine = "",
        string hostName = "",
        string osBuild = "",
        string privilegeState = "",
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            return CreateFailure(imagePath, jobId, displayName, "A memory image path is required.");
        }

        var resolvedPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(imagePath));
        var extension = Path.GetExtension(resolvedPath);
        if (!AgentMemoryActionPolicy.IsSupportedImagePath(resolvedPath))
        {
            return CreateFailure(
                resolvedPath,
                jobId,
                displayName,
                $"Unsupported memory image extension '{extension}'.");
        }

        if (!File.Exists(resolvedPath))
        {
            return CreateFailure(resolvedPath, jobId, displayName, "The selected memory image file does not exist.");
        }

        try
        {
            var info = new FileInfo(resolvedPath);
            if (info.Length <= 0)
            {
                return CreateFailure(
                    resolvedPath,
                    jobId,
                    displayName,
                    "The selected memory image file is empty.");
            }

            var hash = await ComputeSha256Async(resolvedPath, cancellationToken).ConfigureAwait(false);
            var normalizedDisplayName = string.IsNullOrWhiteSpace(displayName)
                ? info.Name
                : displayName.Trim();
            return new MemoryImageRecord
            {
                ImageId = CreateImageId(resolvedPath, hash),
                JobId = jobId,
                Status = MemoryImageStatus.Imported,
                ImportedUtc = DateTime.UtcNow,
                SourcePath = resolvedPath,
                FilePath = resolvedPath,
                DisplayName = normalizedDisplayName,
                ImageFormat = NormalizeImageFormat(extension),
                FileSizeBytes = info.Length,
                Sha256Hash = hash,
                HostName = string.IsNullOrWhiteSpace(hostName) ? Environment.MachineName : hostName,
                OsBuild = osBuild,
                AcquisitionTool = acquisitionTool,
                AcquisitionToolVersion = acquisitionToolVersion,
                AcquisitionCommandLine = acquisitionCommandLine,
                PrivilegeState = privilegeState,
                Source = "AgentMemoryImageImport"
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            return CreateFailure(resolvedPath, jobId, displayName, ex.Message);
        }
    }

    public string ResolveMemoryOutputDirectory(string imageId)
    {
        var memoryRoot = _sessionPaths?.MemoryDirectory ?? SessionPathService.GetDefaultMemoryDirectory();
        var safeImageId = SanitizePathPart(string.IsNullOrWhiteSpace(imageId) ? Guid.NewGuid().ToString("N") : imageId);
        return Path.Combine(memoryRoot, safeImageId);
    }

    private static MemoryImageRecord CreateFailure(string path, Guid? jobId, string displayName, string error)
    {
        var resolvedPath = string.IsNullOrWhiteSpace(path)
            ? string.Empty
            : Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
        return new MemoryImageRecord
        {
            ImageId = CreateImageId(resolvedPath, error),
            JobId = jobId,
            Status = MemoryImageStatus.Failed,
            ImportedUtc = DateTime.UtcNow,
            SourcePath = resolvedPath,
            FilePath = resolvedPath,
            DisplayName = string.IsNullOrWhiteSpace(displayName)
                ? Path.GetFileName(resolvedPath)
                : displayName.Trim(),
            ImageFormat = NormalizeImageFormat(Path.GetExtension(resolvedPath)),
            HostName = Environment.MachineName,
            AcquisitionTool = "Analyst import",
            ErrorMessage = error,
            Source = "AgentMemoryImageImport"
        };
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            options: FileOptions.SequentialScan | FileOptions.Asynchronous);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string CreateImageId(string path, string discriminator)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{path}|{discriminator}"));
        return Convert.ToHexString(bytes).ToLowerInvariant()[..32];
    }

    private static string NormalizeImageFormat(string extension)
        => string.IsNullOrWhiteSpace(extension) ? "unknown" : extension.TrimStart('.').ToLowerInvariant();

    private static string SanitizePathPart(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.ToCharArray();
        for (var index = 0; index < chars.Length; index++)
        {
            if (invalid.Contains(chars[index]))
            {
                chars[index] = '_';
            }
        }

        return new string(chars).Trim();
    }
}
