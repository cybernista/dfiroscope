namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlCatalogAcquisitionOptions
{
    public long MaxArchiveBytes { get; init; } = 256L * 1024 * 1024 * 1024;

    public long MaxExtractedBytes { get; init; } = 512L * 1024 * 1024 * 1024;

    public int MaxArchiveEntries { get; init; } = 64;

    public double MaxCompressionRatio { get; init; } = 1_000;

    public long DiskReserveBytes { get; init; } = 1024L * 1024 * 1024;

    public int MaxDownloadAttempts { get; init; } = 3;

    public TimeSpan ReadStallTimeout { get; init; } = TimeSpan.FromMinutes(2);

    public int CopyBufferBytes { get; init; } = 1024 * 1024;
}

public interface INsrlCatalogStorageProbe
{
    long GetAvailableFreeSpace(string path);
}

public sealed class NsrlCatalogStorageProbe : INsrlCatalogStorageProbe
{
    public long GetAvailableFreeSpace(string path)
    {
        var root = Path.GetPathRoot(Path.GetFullPath(path))
            ?? throw new InvalidDataException("The NSRL catalog root has no storage volume.");
        return new DriveInfo(root).AvailableFreeSpace;
    }
}
