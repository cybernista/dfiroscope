using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class PeAnalysisRowViewModel : ViewModelBase
{
    private readonly PeAnalysisRecord _record;
    private PeStringSummaryView? _stringSummary;

    public PeAnalysisRowViewModel(PeAnalysisRecord record)
    {
        _record = record;
    }

    public string AnalysisId => _record.AnalysisId;

    public string SourceKind => _record.SourceKind.ToString();

    public bool IsDiskSource => _record.SourceKind == PeAnalysisSourceKind.ProcessImage;

    public string SourceView => IsDiskSource ? "PE On Disk" : "PE From Memory/Dump";

    public string SourceArtifactId => _record.SourceArtifactId;

    public string Status => _record.Status.ToString();

    public DateTime AnalyzedUtc => _record.AnalyzedUtc;

    public string AnalyzedDisplay => _record.AnalyzedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string FilePath => _record.FilePath;

    public long FileSizeBytes => _record.FileSizeBytes;

    public string FileSizeDisplay => FormatBytes(_record.FileSizeBytes);

    public string Machine => _record.Machine;

    public string Subsystem => _record.Subsystem;

    public string PeKind => _record.PeKind;

    public string EntryPoint => _record.EntryPoint;

    public string ImageBase => _record.ImageBase;

    public int SectionCount => _record.SectionCount;

    public int ImportCount => _record.ImportCount;

    public int ExportCount => _record.ExportCount;

    public int PrintableStringCount => _record.PrintableStringCount;

    public string StringAnalysisStatus => _record.StringAnalysisStatus.ToString();

    public string PrintableStringSamplesDisplay
    {
        get
        {
            if (_record.StringAnalysisStatus != PeStringAnalysisStatus.Completed)
            {
                return _record.StringAnalysisStatus.ToString();
            }

            var summary = ParseStringSummary();
            return summary.SampleCount == 0
                ? "0"
                : $"{summary.SampleCount}/{summary.TotalCount}";
        }
    }

    public string StringTruncationStatus
    {
        get
        {
            if (_record.StringAnalysisStatus != PeStringAnalysisStatus.Completed)
            {
                return _record.StringAnalysisStatus.ToString();
            }

            var summary = ParseStringSummary();
            if (summary.IsSampleTruncated && summary.IsScanTruncated)
            {
                return "Samples and scan truncated";
            }

            if (summary.IsSampleTruncated)
            {
                return "Samples truncated";
            }

            if (summary.IsScanTruncated)
            {
                return "Scan truncated";
            }

            return "Complete";
        }
    }

    public string PrintableStringsPreview
    {
        get
        {
            var summary = ParseStringSummary();
            return summary.Samples.Count == 0
                ? string.Empty
                : string.Join(Environment.NewLine, summary.Samples.Take(20).Select(sample => $"{sample.Encoding}: {sample.Value}"));
        }
    }

    public string Sha256Hash => _record.Sha256Hash;

    public string ErrorMessage => _record.ErrorMessage;

    public AuthenticodeVerificationRecord? AuthenticodeVerification => _record.AuthenticodeVerification;

    public bool MatchesStringFilter(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return true;
        }

        return Contains(PrintableStringsPreview, filter) ||
               Contains(FilePath, filter) ||
               Contains(SourceArtifactId, filter) ||
               Contains(Sha256Hash, filter) ||
               Contains(ErrorMessage, filter);
    }

    public InspectorPayload ToInspectorPayload()
    {
        var contentSections = BuildContentSections();
        var performanceRowCount = contentSections.First(section => section.Title == "Performance").Rows.Count;
        var properties = new List<PropertyItemViewModel>
        {
            new("Identity", "Analysis ID", AnalysisId),
            new("Identity", "Source Kind", SourceKind),
            new("Identity", "Source Artifact ID", string.IsNullOrWhiteSpace(SourceArtifactId) ? "<none>" : SourceArtifactId),
            new("Process", "Process Key", _record.ProcessKey),
            new("Process", "Process Entity", _record.ProcessEntityId),
            new("Provenance", "Source Run", _record.SourceRunId),
            new("Provenance", "Ingestion Job", _record.IngestionJobId),
            new("Process", "Process Name", _record.ProcessName),
            new("Process", "PID", _record.ProcessId.ToString()),
            new("File", "Path", string.IsNullOrWhiteSpace(FilePath) ? "<none>" : FilePath),
            new("File", "Size", FileSizeDisplay),
            new("File", "SHA256", string.IsNullOrWhiteSpace(Sha256Hash) ? "<none>" : Sha256Hash),
            new("File", "MD5", string.IsNullOrWhiteSpace(_record.Md5Hash) ? "<none>" : _record.Md5Hash),
            new("Authenticode", "Signature Kind", AuthenticodeVerification?.SignatureKind.ToString() ?? "<not captured>"),
            new("Authenticode", "Verification Status", AuthenticodeVerification?.VerificationStatus.ToString() ?? "<not captured>"),
            new("Authenticode", "Publisher", Display(AuthenticodeVerification?.Publisher)),
            new("Authenticode", "Signer Subject", Display(AuthenticodeVerification?.SignerSubject)),
            new("Authenticode", "Thumbprint", Display(AuthenticodeVerification?.CertificateThumbprint)),
            new("Authenticode", "Issuer", Display(AuthenticodeVerification?.Issuer)),
            new("Authenticode", "Timestamp", AuthenticodeVerification?.TimestampUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "<none>"),
            new("Authenticode", "Verification Policy", Display(AuthenticodeVerification?.VerificationPolicy)),
            new("Authenticode", "Revocation", AuthenticodeVerification == null
                ? "<not captured>"
                : $"{AuthenticodeVerification.RevocationMode} / {AuthenticodeVerification.RevocationStatus}"),
            new("Authenticode", "Safety Meaning", "A valid signature identifies a publisher; it does not establish benignness."),
            new("PE Header", "Status", Status),
            new("PE Header", "Kind", string.IsNullOrWhiteSpace(PeKind) ? "<none>" : PeKind),
            new("PE Header", "Machine", string.IsNullOrWhiteSpace(Machine) ? "<none>" : Machine),
            new("PE Header", "Subsystem", string.IsNullOrWhiteSpace(Subsystem) ? "<none>" : Subsystem),
            new("PE Header", "Image Base", string.IsNullOrWhiteSpace(ImageBase) ? "<none>" : ImageBase),
            new("PE Header", "Entry Point", string.IsNullOrWhiteSpace(EntryPoint) ? "<none>" : EntryPoint),
            new("PE Header", "Linker Timestamp", _record.LinkerTimestampUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "<none>"),
            new("Contents", "Sections", SectionCount.ToString()),
            new("Contents", "Imports", ImportCount.ToString()),
            new("Contents", "Exports", ExportCount.ToString()),
            new("Contents", "Printable Strings", PrintableStringCount.ToString()),
            new("Contents", "String Analysis", StringAnalysisStatus),
            new("Contents", "String Samples", PrintableStringSamplesDisplay),
            new("Contents", "String Truncation", StringTruncationStatus),
            new("Analysis", "Analyzed", AnalyzedDisplay),
            new("Analysis", "Performance", performanceRowCount == 0 ? "<none>" : $"{performanceRowCount} timing phase(s)"),
            new("Analysis", "Source", string.IsNullOrWhiteSpace(_record.Source) ? "<none>" : _record.Source),
            new("Analysis", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
        };

        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.PeAnalysis,
            TargetKind = "PeAnalysis",
            TargetTable = "PeAnalyses",
            TargetId = AnalysisId,
            ArtifactId = AnalysisId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            ProcessKey = _record.ProcessKey,
            ProcessId = _record.ProcessId,
            ProcessName = _record.ProcessName,
            DisplayPath = FilePath,
            Header = $"{SourceView} | {Status}",
            Subtitle = string.IsNullOrWhiteSpace(FilePath) ? _record.ProcessName : FilePath,
            EmptyStateMessage = "Select a PE analysis record to inspect it here.",
            Properties = properties,
            ContentSections = contentSections
        };
    }

    private IReadOnlyList<InspectorContentSection> BuildContentSections()
    {
        var sectionRows = ParseJsonArray(_record.SectionsJson, section => new InspectorContentRow(
            GetJsonValue(section, "Name", "<unnamed>"),
            $"VA {GetJsonValue(section, "VirtualAddress", "<unknown>")}; {GetJsonValue(section, "VirtualSize", "0")} bytes",
            $"Raw {GetJsonValue(section, "RawSize", "0")} bytes at {GetJsonValue(section, "RawPointer", "<unknown>")}; {GetJsonValue(section, "Characteristics", "<none>")}"));

        var importRows = ParseJsonArray(_record.ImportsJson, import => new InspectorContentRow(
            GetJsonValue(import, "Library", "<unknown library>"),
            GetJsonValue(import, "Name", "<unnamed symbol>")));

        var exportRows = ParseJsonArray(_record.ExportsJson, export => new InspectorContentRow(
            export.ValueKind == JsonValueKind.String ? export.GetString() ?? "<unnamed export>" : GetJsonValue(export, "Name", "<unnamed export>"),
            export.ValueKind == JsonValueKind.String ? "Exported symbol" : GetJsonValue(export, "Ordinal", string.Empty),
            export.ValueKind == JsonValueKind.String ? string.Empty : GetJsonValue(export, "Address", string.Empty)));

        var versionRows = ParseJsonObject(_record.VersionInfoJson)
            .Select(property => new InspectorContentRow(
                property.Name,
                string.IsNullOrEmpty(property.Value) ? "<empty>" : property.Value))
            .ToList();

        var stringRows = ParseStringRows();
        var stringDescription = _record.StringAnalysisStatus == PeStringAnalysisStatus.Completed
            ? $"{PrintableStringCount} printable string(s) found; {stringRows.Count} sample(s) retained. {StringTruncationStatus}."
            : $"String extraction status: {StringAnalysisStatus}. No string samples are shown until extraction completes.";

        var performanceRows = ParseJsonObject(_record.PerformanceJson)
            .Select(property => new InspectorContentRow(property.Name, property.Value))
            .ToList();
        var authenticodeRows = BuildAuthenticodeRows();

        return
        [
            new InspectorContentSection("Sections", $"{SectionCount} PE section(s) parsed from the image.", sectionRows, isExpanded: true),
            new InspectorContentSection("Imports", $"{ImportCount} imported symbol(s).", importRows, isExpanded: true),
            new InspectorContentSection("Exports", $"{ExportCount} exported symbol(s).", exportRows),
            new InspectorContentSection("Version information", "Version-resource fields available on the file.", versionRows),
            new InspectorContentSection(
                "Authenticode verification",
                AuthenticodeVerification == null
                    ? "No durable Authenticode observation is attached to this PE analysis."
                    : "Recorded Windows trust result. A valid signature identifies a publisher; it does not establish benignness.",
                authenticodeRows,
                isExpanded: true),
            new InspectorContentSection("Printable strings", stringDescription, stringRows),
            new InspectorContentSection("Performance", "PE analysis phase timings in milliseconds.", performanceRows)
        ];
    }

    private IReadOnlyList<InspectorContentRow> BuildAuthenticodeRows()
    {
        var verification = AuthenticodeVerification;
        if (verification == null)
        {
            return [];
        }

        return
        [
            new InspectorContentRow("Verification ID", verification.VerificationId),
            new InspectorContentRow("Analysis ID", verification.AnalysisId),
            new InspectorContentRow("Signature", $"{verification.SignatureKind} / {verification.VerificationStatus}"),
            new InspectorContentRow("Publisher", Display(verification.Publisher)),
            new InspectorContentRow("Signer subject", Display(verification.SignerSubject)),
            new InspectorContentRow("Certificate thumbprint", Display(verification.CertificateThumbprint)),
            new InspectorContentRow("Issuer", Display(verification.Issuer)),
            new InspectorContentRow("Timestamp subject", Display(verification.TimestampSubject)),
            new InspectorContentRow("Timestamp UTC", verification.TimestampUtc?.ToString("O") ?? "<none>"),
            new InspectorContentRow("Verification time UTC", verification.VerificationTimeUtc.ToString("O")),
            new InspectorContentRow("Policy", verification.VerificationPolicy),
            new InspectorContentRow("Revocation", $"{verification.RevocationMode} / {verification.RevocationStatus}"),
            new InspectorContentRow("Native status", Display(verification.NativeStatusCode)),
            new InspectorContentRow("Diagnostic", $"{verification.DiagnosticCode}: {verification.DiagnosticText}"),
            new InspectorContentRow("Source run", Display(verification.SourceRunId)),
            new InspectorContentRow("Ingestion job", Display(verification.IngestionJobId)),
            new InspectorContentRow("File SHA256", Display(verification.Sha256Hash))
        ];
    }

    private static string Display(string? value)
        => string.IsNullOrWhiteSpace(value) ? "<none>" : value;

    private IReadOnlyList<InspectorContentRow> ParseStringRows()
    {
        if (_record.StringAnalysisStatus != PeStringAnalysisStatus.Completed || string.IsNullOrWhiteSpace(_record.StringSummaryJson))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(_record.StringSummaryJson);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                return root.EnumerateArray()
                    .Where(sample => sample.ValueKind == JsonValueKind.String)
                    .Select(sample => new InspectorContentRow("ASCII", sample.GetString() ?? string.Empty))
                    .Where(row => !string.IsNullOrWhiteSpace(row.Value))
                    .ToList();
            }

            if (root.ValueKind != JsonValueKind.Object)
            {
                return [];
            }

            var rows = root.EnumerateObject()
                .Where(property => !string.Equals(property.Name, "Samples", StringComparison.OrdinalIgnoreCase))
                .Select(property => new InspectorContentRow(property.Name, JsonValueToDisplay(property.Value), "Metadata"))
                .ToList();

            if (TryGetJsonProperty(root, "Samples", out var samples) && samples.ValueKind == JsonValueKind.Array)
            {
                rows.AddRange(samples.EnumerateArray()
                    .Select(sample => sample.ValueKind == JsonValueKind.String
                        ? new InspectorContentRow("ASCII", sample.GetString() ?? string.Empty, "Sample")
                        : new InspectorContentRow(
                            GetJsonValue(sample, "Encoding", "ASCII"),
                            GetJsonValue(sample, "Value", string.Empty),
                            "Sample"))
                    .Where(row => !string.IsNullOrWhiteSpace(row.Value)));
            }

            return rows;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static IReadOnlyList<InspectorContentRow> ParseJsonArray(
        string json,
        Func<JsonElement, InspectorContentRow> projector)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind != JsonValueKind.Array
                ? []
                : document.RootElement.EnumerateArray().Select(projector).ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static IReadOnlyList<(string Name, string Value)> ParseJsonObject(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind != JsonValueKind.Object
                ? []
                : document.RootElement.EnumerateObject()
                    .Select(property => (property.Name, JsonValueToDisplay(property.Value)))
                    .ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string GetJsonValue(JsonElement element, string name, string fallback)
        => TryGetJsonProperty(element, name, out var property) ? JsonValueToDisplay(property) : fallback;

    private static bool TryGetJsonProperty(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string JsonValueToDisplay(JsonElement value)
        => value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Null => string.Empty,
            _ => value.GetRawText()
        };

    private PeStringSummaryView ParseStringSummary()
    {
        if (_stringSummary != null)
        {
            return _stringSummary;
        }

        if (string.IsNullOrWhiteSpace(_record.StringSummaryJson))
        {
            _stringSummary = PeStringSummaryView.Empty(_record.PrintableStringCount);
            return _stringSummary;
        }

        try
        {
            using var document = JsonDocument.Parse(_record.StringSummaryJson);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                var legacySamples = root
                    .EnumerateArray()
                    .Where(element => element.ValueKind == JsonValueKind.String)
                    .Select(element => new PeStringSampleView("ASCII", element.GetString() ?? string.Empty))
                    .Where(sample => !string.IsNullOrEmpty(sample.Value))
                    .ToList();

                _stringSummary = new PeStringSummaryView(
                    _record.PrintableStringCount,
                    legacySamples,
                    legacySamples.Count < _record.PrintableStringCount,
                    false);
                return _stringSummary;
            }

            if (root.ValueKind != JsonValueKind.Object)
            {
                _stringSummary = PeStringSummaryView.Empty(_record.PrintableStringCount);
                return _stringSummary;
            }

            var totalCount = GetInt(root, "totalCount", _record.PrintableStringCount);
            var isSampleTruncated = GetBool(root, "isSampleTruncated");
            var isScanTruncated = GetBool(root, "isScanTruncated");
            var samples = new List<PeStringSampleView>();
            if (root.TryGetProperty("samples", out var samplesElement) && samplesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var sampleElement in samplesElement.EnumerateArray())
                {
                    if (sampleElement.ValueKind == JsonValueKind.String)
                    {
                        var value = sampleElement.GetString() ?? string.Empty;
                        if (!string.IsNullOrEmpty(value))
                        {
                            samples.Add(new PeStringSampleView("ASCII", value));
                        }

                        continue;
                    }

                    if (sampleElement.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var encoding = sampleElement.TryGetProperty("encoding", out var encodingElement)
                        ? encodingElement.GetString() ?? "ASCII"
                        : "ASCII";
                    var sampleValue = sampleElement.TryGetProperty("value", out var valueElement)
                        ? valueElement.GetString() ?? string.Empty
                        : string.Empty;
                    if (!string.IsNullOrEmpty(sampleValue))
                    {
                        samples.Add(new PeStringSampleView(encoding, sampleValue));
                    }
                }
            }

            _stringSummary = new PeStringSummaryView(totalCount, samples, isSampleTruncated, isScanTruncated);
            return _stringSummary;
        }
        catch
        {
            _stringSummary = PeStringSummaryView.Empty(_record.PrintableStringCount);
            return _stringSummary;
        }
    }

    private static int GetInt(JsonElement element, string propertyName, int fallback)
    {
        return element.TryGetProperty(propertyName, out var property) && property.TryGetInt32(out var value)
            ? value
            : fallback;
    }

    private static bool GetBool(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) &&
               property.ValueKind is JsonValueKind.True or JsonValueKind.False &&
               property.GetBoolean();
    }

    private static bool Contains(string value, string filter)
        => !string.IsNullOrEmpty(value) &&
           value.Contains(filter, StringComparison.OrdinalIgnoreCase);

    private static string FormatJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return "<none>";
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            return json;
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
        }

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0 ? $"{bytes} B" : $"{value:F1} {units[unit]}";
    }

    private sealed record PeStringSummaryView(
        int TotalCount,
        IReadOnlyList<PeStringSampleView> Samples,
        bool IsSampleTruncated,
        bool IsScanTruncated)
    {
        public int SampleCount => Samples.Count;

        public static PeStringSummaryView Empty(int totalCount)
            => new(totalCount, Array.Empty<PeStringSampleView>(), false, false);
    }

    private sealed record PeStringSampleView(string Encoding, string Value);
}
