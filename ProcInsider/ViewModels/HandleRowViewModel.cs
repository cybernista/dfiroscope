using ProcInsider.Models;
using System;
using System.Collections.Generic;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for a single handle row in the handles DataGrid.
/// </summary>
public class HandleRowViewModel : ViewModelBase
{
    private readonly HandleInfo _handleInfo;

    public HandleRowViewModel(HandleInfo handleInfo)
    {
        _handleInfo = handleInfo;
    }

    public string HandleValue => _handleInfo.HandleValue;
    public string ProcessEntityId => _handleInfo.ProcessEntityId;
    public string SourceRunId => _handleInfo.SourceRunId;
    public string IngestionJobId => _handleInfo.IngestionJobId;
    public ulong HandleValueNumeric => _handleInfo.HandleValueNumeric;
    public string ObjectType => _handleInfo.ObjectType;
    public string ObjectName => _handleInfo.ObjectName;
    public string GrantedAccess => _handleInfo.GrantedAccess;
    public uint GrantedAccessValue => _handleInfo.GrantedAccessValue;
    public string HandleAttributes => _handleInfo.HandleAttributes;
    public uint HandleAttributesValue => _handleInfo.HandleAttributesValue;
    public string ObjectAddress => _handleInfo.ObjectAddress;
    public string Status => _handleInfo.StatusDisplay;
    public bool IsStale => _handleInfo.IsStale;
    public DateTime? LastSeenUtc => _handleInfo.LastSeenUtc;
    public string LastSeen => LastSeenUtc.HasValue
        ? LastSeenUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        : string.Empty;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.Handle,
            TargetKind = "Handle",
            TargetTable = "Handles",
            ArtifactId = $"{HandleValue}|{ObjectType}|{ObjectAddress}|{ObjectName}",
            Header = string.IsNullOrWhiteSpace(ObjectName) || ObjectName == "<not available>"
                ? $"{ObjectType} Handle"
                : ObjectName,
            Subtitle = $"Handle {HandleValue} | {ObjectType} | {Status}",
            EmptyStateMessage = "Select a handle to inspect it here.",
            RawText = $"Name: {ObjectName}{System.Environment.NewLine}Access: {GrantedAccess}{System.Environment.NewLine}Attributes: {HandleAttributes}{System.Environment.NewLine}Object Address: {ObjectAddress}",
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Handle", HandleValue),
                new("Identity", "Process Entity", ProcessEntityId),
                new("Provenance", "Source Run", SourceRunId),
                new("Provenance", "Ingestion Job", IngestionJobId),
                new("Identity", "Handle Value", HandleValueNumeric.ToString()),
                new("Lifecycle", "Status", Status),
                new("Lifecycle", "Last Seen", LastSeen),
                new("Object", "Type", ObjectType),
                new("Object", "Name", ObjectName),
                new("Security", "Granted Access", GrantedAccess),
                new("Security", "Granted Access Value", $"0x{GrantedAccessValue:X8}"),
                new("Runtime", "Attributes", HandleAttributes),
                new("Runtime", "Attributes Value", $"0x{HandleAttributesValue:X8}"),
                new("Runtime", "Object Address", ObjectAddress)
            }
        };
    }
}
