using System.Globalization;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Features.Infrastructure;

/// <summary>
/// Immutable display projection for one Server row. The transport DTO remains evidence/query
/// vocabulary; WPF-specific timestamp, uncertainty, relationship and risk formatting lives here.
/// </summary>
public sealed class InfrastructureViewerQueryRowViewModel
{
    public InfrastructureViewerQueryRowViewModel(InfrastructureViewerQueryRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        RowId = row.RowId;
        Kind = row.Kind;
        CaseId = row.CaseId;
        HostId = row.HostId;
        AgentId = row.AgentId;
        CaptureId = row.CaptureId;
        SourceRunId = row.SourceRunId;
        ProcessEntityId = row.ProcessEntityId;
        ProcessKey = row.ProcessKey;
        ProcessId = row.ProcessId;
        DisplayName = row.DisplayName;
        Category = row.Category;
        Status = row.Status;
        NativeTimestampUtc = row.NativeTimestampUtc;
        ServerReceiptTimeUtc = row.ServerReceiptTimeUtc;
        ClockUncertaintyMilliseconds = row.ClockUncertaintyMilliseconds;
        Severity = row.Severity;
        RiskScore = row.RiskScore;
        RelationshipAmbiguous = row.RelationshipAmbiguous;
        Fields = row.Fields;
    }

    public string RowId { get; }
    public InfrastructureViewerQueryKind Kind { get; }
    public string CaseId { get; }
    public string HostId { get; }
    public string AgentId { get; }
    public string CaptureId { get; }
    public string SourceRunId { get; }
    public string ProcessEntityId { get; }
    public string ProcessKey { get; }
    public int? ProcessId { get; }
    public string DisplayName { get; }
    public string Category { get; }
    public string Status { get; }
    public DateTime? NativeTimestampUtc { get; }
    public DateTime? ServerReceiptTimeUtc { get; }
    public long ClockUncertaintyMilliseconds { get; }
    public int Severity { get; }
    public double? RiskScore { get; }
    public bool RelationshipAmbiguous { get; }
    public IReadOnlyDictionary<string, string> Fields { get; }

    public string NativeTimestampDisplay => FormatUtc(NativeTimestampUtc);
    public string ServerReceiptTimeDisplay => FormatUtc(ServerReceiptTimeUtc);
    public string ClockUncertaintyDisplay => $"±{ClockUncertaintyMilliseconds:N0} ms";
    public string RelationshipDisplay => RelationshipAmbiguous ? "Ambiguous" : "Not marked ambiguous";
    public string RiskDisplay => RiskScore?.ToString("0.##", CultureInfo.InvariantCulture) ?? string.Empty;

    private static string FormatUtc(DateTime? value) => value == null
        ? string.Empty
        : value.Value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'", CultureInfo.InvariantCulture);
}
