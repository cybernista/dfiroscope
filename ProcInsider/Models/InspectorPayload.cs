using System.Collections.Generic;
using ProcInsider.ViewModels;

namespace ProcInsider.Models;

/// <summary>
/// Normalized payload for the shared inspector pane.
/// </summary>
public class InspectorPayload
{
    public InspectorArtifactKind ArtifactKind { get; set; }

    public string TargetKind { get; set; } = string.Empty;

    public string TargetTable { get; set; } = string.Empty;

    public string TargetId { get; set; } = string.Empty;

    public string ArtifactId { get; set; } = string.Empty;

    public string CaseId { get; set; } = string.Empty;

    public string EvidenceSessionId { get; set; } = string.Empty;

    public string CaptureId { get; set; } = string.Empty;

    public string SourceIdentityId { get; set; } = string.Empty;

    public string HostId { get; set; } = string.Empty;

    public string ExecutionRootId { get; set; } = string.Empty;

    public string SourceRunId { get; set; } = string.Empty;

    public string IngestionJobId { get; set; } = string.Empty;

    public string ProcessKey { get; set; } = string.Empty;

    public int ProcessId { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string DisplayPath { get; set; } = string.Empty;

    public string Header { get; set; } = string.Empty;

    public string Subtitle { get; set; } = string.Empty;

    public string EmptyStateMessage { get; set; } = string.Empty;

    public IReadOnlyList<PropertyItemViewModel> Properties { get; set; } = [];

    /// <summary>
    /// Optional structured content shown below the property grid. This is used for
    /// artifact payloads whose detail data is more useful as expandable tables than raw text.
    /// </summary>
    public IReadOnlyList<InspectorContentSection> ContentSections { get; set; } = [];

    public string RawText { get; set; } = string.Empty;

    public string RawXml { get; set; } = string.Empty;
}

/// <summary>
/// One expandable table in the shared Details inspector.
/// </summary>
public sealed class InspectorContentSection
{
    public InspectorContentSection(
        string title,
        string description,
        IReadOnlyList<InspectorContentRow> rows,
        bool isExpanded = false)
    {
        Title = title;
        Description = description;
        Rows = rows;
        IsExpanded = isExpanded;
    }

    public string Title { get; }

    public string Description { get; }

    public IReadOnlyList<InspectorContentRow> Rows { get; }

    public bool IsExpanded { get; set; }

    public string DisplayTitle => $"{Title} ({Rows.Count})";
}

/// <summary>
/// A generic three-column row used by an inspector content table.
/// </summary>
public sealed record InspectorContentRow(string Item, string Value, string Details = "");
