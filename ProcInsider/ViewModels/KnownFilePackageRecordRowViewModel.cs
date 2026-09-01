using ProcInsider.Models.KnownFiles;

namespace ProcInsider.ViewModels;

public sealed class KnownFilePackageRecordRowViewModel
{
    private readonly KnownFilePackageRecord _record;

    public KnownFilePackageRecordRowViewModel(KnownFilePackageRecord record)
    {
        _record = record;
    }

    public string FileNamesDisplay => _record.FileNames.Count == 0
        ? "<not reported>"
        : string.Join(Environment.NewLine, _record.FileNames);

    public string FileSizeDisplay => FormatBytes(_record.FileSizeBytes);

    public string ProductDisplay => Join(_record.ProductName, _record.ProductVersion);

    public string ManufacturerDisplay => Empty(_record.Manufacturer);

    public string OperatingSystemDisplay => Join(
        _record.OperatingSystemName,
        _record.OperatingSystemVersion);

    public string LanguageDisplay => Empty(_record.Language);

    public string ApplicationTypeDisplay => Empty(_record.ApplicationType);

    public string ProviderSourceDisplay => Empty(_record.ProviderSource);

    private static string Join(string name, string version)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return Empty(version);
        }

        return string.IsNullOrWhiteSpace(version) ? name : $"{name} ({version})";
    }

    private static string Empty(string value)
        => string.IsNullOrWhiteSpace(value) ? "<not reported>" : value;

    public static string FormatBytes(long? bytes)
    {
        if (!bytes.HasValue || bytes.Value < 0)
        {
            return "<not available>";
        }

        if (bytes.Value < 1024)
        {
            return $"{bytes.Value:N0} B";
        }

        if (bytes.Value < 1024L * 1024)
        {
            return $"{bytes.Value / 1024d:N1} KB";
        }

        if (bytes.Value < 1024L * 1024 * 1024)
        {
            return $"{bytes.Value / (1024d * 1024):N1} MB";
        }

        return $"{bytes.Value / (1024d * 1024 * 1024):N2} GB";
    }
}
