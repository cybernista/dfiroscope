using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Data;
using ProcInsider.Models;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed record PrefetchRunRow(int Slot, string RecordedUtc);
internal sealed record PrefetchFileRow(int Reference, string Name, string Extension, string RecordedPath, string PathState);
internal sealed record PrefetchVolumeRow(int Volume, string RecordedPath, string SerialNumber, string CreatedUtc, string RecordedDirectoryCount);
internal sealed record PrefetchFolderRow(int Volume, string RecordedPath, string PathState);
internal sealed record PrefetchPresentationData(PropertyItemViewModel[] Summary, PrefetchRunRow[] Runs,
    PrefetchFileRow[] Files, PrefetchVolumeRow[] Volumes, PrefetchFolderRow[] Folders, string Qualification);

/// <summary>Transient presentation of parser v1 fields; never resolves paths or attributes referenced files to execution.</summary>
internal sealed class PrefetchPresentation : ViewModelBase
{
    public const string Interpretation = "Prefetch supports evidence of program execution. Referenced files are startup observations; their presence does not prove that they executed. Recorded counts and recent times are a limited artifact history, not a complete execution log. User, parent process and full command line are not recorded here.";
    private string _fileSearch = "", _folderSearch = "";
    public PrefetchPresentationData Data { get; }
    public string InterpretationText => Interpretation;
    public ICollectionView FilesView { get; }
    public ICollectionView FoldersView { get; }
    public string FileSearch { get => _fileSearch; set { if (SetProperty(ref _fileSearch, value)) FilesView.Refresh(); } }
    public string FolderSearch { get => _folderSearch; set { if (SetProperty(ref _folderSearch, value)) FoldersView.Refresh(); } }
    public PrefetchPresentation(PrefetchPresentationData data)
    {
        Data = data;
        FilesView = new ListCollectionView((IList)data.Files);
        FilesView.Filter = row => row is PrefetchFileRow file && file.RecordedPath.Contains(FileSearch, StringComparison.OrdinalIgnoreCase);
        FoldersView = new ListCollectionView((IList)data.Folders);
        FoldersView.Filter = row => row is PrefetchFolderRow folder && folder.RecordedPath.Contains(FolderSearch, StringComparison.OrdinalIgnoreCase);
    }

    internal static PrefetchPresentationData? Project(ForensicArtifactResultRow row,
        IReadOnlyList<ForensicArtifactResultProperty> properties, CancellationToken token)
    {
        if (row.ArtifactType != "Prefetch") return null;
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in properties)
        {
            token.ThrowIfCancellationRequested();
            using var document = JsonDocument.Parse(property.ValueType == "String" ? JsonSerializer.Serialize(property.Value) : property.Value ?? "null", new JsonDocumentOptions { MaxDepth = 32 });
            fields.Add(property.Name, document.RootElement.Clone());
        }
        JsonElement Field(string name) => fields.GetValueOrDefault(name);
        var summary = new List<PropertyItemViewModel>();
        void Add(string name, string value) => summary.Add(new("Prefetch", name, value));
        if (row.ParserId != "dfiroscope.prefetch" || row.ParserVersion != "1" || !Number(Field("PayloadVersion"), out var payload) || payload != 1)
        {
            Add("Readable interpretation", "Unavailable for this parser or payload version. See Technical details for the recorded fields.");
            return new(summary.ToArray(), [], [], [], [], "This result uses an unrecognized Prefetch payload. No field interpretation was attempted.");
        }
        var warnings = new List<string>();
        var program = NativeText(Field("ExecutableName"));
        Add("Program", program.Path); Add("Program name state", program.State);
        Add("Prefetch source file", row.SourcePath);
        Add("Last recorded run (UTC)", Timestamp(Field("LatestRecordedRunUtc")));
        Add("Recorded executions", Count(Field("RunCount")));
        var runs = new List<PrefetchRunRow>();
        foreach (var entry in Array(Field("RecordedRunTimes"), "execution history"))
        {
            token.ThrowIfCancellationRequested();
            var utc = Member(entry, "Utc");
            if (utc.ValueKind == JsonValueKind.Null && Number(Member(entry, "RawFileTime"), out var raw) && raw == 0) continue;
            var slot = Number(Member(entry, "Slot"), out var number) && number <= int.MaxValue ? (int)number : -1;
            var recorded = utc.ValueKind == JsonValueKind.Null ? Unknown("execution timestamp") : Timestamp(utc);
            runs.Add(new(slot, recorded));
        }
        // Parser slots retain their original order; raw FILETIME and slot metadata remain in Technical details.
        Add("Recent timestamp entries retained", runs.Count.ToString("N0", CultureInfo.InvariantCulture));
        var files = new List<PrefetchFileRow>();
        foreach (var entry in Array(Field("FileReferences"), "file references"))
        {
            token.ThrowIfCancellationRequested();
            var path = NativeText(Member(entry, "Path"));
            var index = Number(Member(entry, "Index"), out var number) && number <= int.MaxValue ? (int)number : -1;
            var name = path.State == "Known" ? path.Path[(path.Path.LastIndexOf('\\') + 1)..] : "Unknown";
            var dot = name.LastIndexOf('.');
            files.Add(new(index, name, dot >= 0 ? name[dot..] : "", path.Path, path.State));
        }
        Add("File references retained / declared", files.Count.ToString("N0", CultureInfo.InvariantCulture) + " / " + Count(Field("DeclaredMetricCount")));
        var volumes = new List<PrefetchVolumeRow>(); var folders = new List<PrefetchFolderRow>();
        foreach (var entry in Array(Field("Volumes"), "volumes"))
        {
            token.ThrowIfCancellationRequested();
            var index = Number(Member(entry, "Index"), out var number) && number < int.MaxValue ? (int)number + 1 : -1;
            var serial = Number(Member(entry, "SerialNumber"), out var serialNumber) && serialNumber <= uint.MaxValue ? serialNumber.ToString("X8", CultureInfo.InvariantCulture) : "Unknown";
            var path = NativeText(Member(entry, "Path"));
            volumes.Add(new(index, path.Path, serial, Timestamp(Member(entry, "CreationUtc")), Count(Member(entry, "DirectoryCount"))));
            foreach (var directory in Array(Member(entry, "Directories"), "directories"))
            {
                token.ThrowIfCancellationRequested(); var folder = NativeText(directory);
                folders.Add(new(index, folder.Path, folder.State));
            }
        }
        Add("Volumes retained / declared", volumes.Count.ToString("N0", CultureInfo.InvariantCulture) + " / " + Count(Field("DeclaredVolumeCount")));
        Add("Prefetch format version", Count(Field("FormatVersion")));
        Add("Volume time meaning", "Volume creation time describes the volume, not when this program ran.");
        Add("Path meaning", "Recorded volume-qualified paths are preserved. No drive letter or executable path is inferred.");
        foreach (var qualification in Array(Field("Qualifications"), "parser qualifications"))
        {
            if (qualification.ValueKind != JsonValueKind.String) { warnings.Add("A parser qualification could not be read."); continue; }
            warnings.Add(qualification.GetString() switch
            {
                "references-capped" => "Only part of the file reference list was retained.",
                "volumes-capped" => "Only part of the volume list was retained.",
                "directories-capped" => "Only part of a directory list was retained.",
                "invalid-filetime" => "One or more recorded timestamps could not be decoded.",
                "header-name-unavailable" or "header-name-unterminated" => "The recorded program name could not be fully decoded.",
                "text-budget-capped" or "text-capped" or "string-capped" => "Some recorded text is incomplete because the parser reached its retention limit.",
                "string-range-invalid" or "directory-range-invalid" or "volume-reference-range-invalid" => "Some recorded references could not be decoded safely.",
                var code => "Parser qualification: " + code + ". See Technical details."
            });
        }
        return new(summary.ToArray(), runs.ToArray(), files.ToArray(), volumes.ToArray(), folders.ToArray(),
            warnings.Count == 0 ? "No parser qualifications recorded." : string.Join(" ", warnings.Distinct(StringComparer.Ordinal)));

        IEnumerable<JsonElement> Array(JsonElement field, string name)
        {
            if (field.ValueKind == JsonValueKind.Array) return field.EnumerateArray().ToArray();
            warnings.Add("The recorded " + name + " list is unavailable."); return [];
        }
        string Count(JsonElement field) => Number(field, out var value) ? value.ToString("N0", CultureInfo.InvariantCulture) : Unknown("number");
        string Timestamp(JsonElement field)
        {
            if (field.ValueKind == JsonValueKind.Null) return "Not recorded";
            if (field.ValueKind == JsonValueKind.String && field.GetString() is { } text &&
                Regex.IsMatch(text, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?(Z|\+00:00)\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking) &&
                DateTimeOffset.TryParseExact(text, ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", "yyyy-MM-dd'T'HH:mm:sszzz", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz"],
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var value) && value.Offset == TimeSpan.Zero)
                return value.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'", CultureInfo.InvariantCulture);
            return Unknown("UTC timestamp");
        }
        string Unknown(string field) { warnings.Add("A recorded " + field + " is missing or invalid; see Technical details."); return "Unknown"; }
    }
    private static JsonElement Member(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var child) ? child : default;
    private static bool Number(JsonElement value, out ulong number) { number = 0; return value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out number); }
    private static (string Path, string State) NativeText(JsonElement value)
    {
        var text = Member(value, "Value"); var state = Member(value, "State");
        return (text.ValueKind == JsonValueKind.String ? text.GetString()! : "Unknown", state.ValueKind == JsonValueKind.String ? state.GetString()! : "Unknown");
    }
}
