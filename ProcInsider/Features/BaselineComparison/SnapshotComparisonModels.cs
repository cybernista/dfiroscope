using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

public enum SnapshotComparisonVerdict
{
    Known,
    New,
    Missing,
    Changed,
    Noisy,
    Accepted
}

public enum SnapshotComparisonArtifactKind
{
    Unknown,
    Process,
    Module,
    PeAnalysis,
    Event,
    NetworkCapture,
    ZeekNetworkArtifact,
    FilesystemArtifact,
    MemoryImage,
    VolatilityPluginRun,
    MemoryProcess
}

public sealed class SnapshotComparisonFinding
{
    public string FindingId { get; set; } = Guid.NewGuid().ToString("N");
    public SnapshotComparisonArtifactKind ArtifactKind { get; set; } = SnapshotComparisonArtifactKind.Unknown;
    public SnapshotComparisonVerdict Verdict { get; set; } = SnapshotComparisonVerdict.Known;
    public string StableKey { get; set; } = string.Empty;
    public string Fingerprint { get; set; } = string.Empty;
    public string BaselineFingerprint { get; set; } = string.Empty;
    public string CurrentFingerprint { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string BaselineSummary { get; set; } = string.Empty;
    public string CurrentSummary { get; set; } = string.Empty;
    public string Explanation { get; set; } = string.Empty;
    public string ChangedFields { get; set; } = string.Empty;
    public string PolicyRuleId { get; set; } = string.Empty;
}

public sealed class SnapshotComparisonResult
{
    public string BaselineSnapshotPath { get; set; } = string.Empty;
    public string CurrentSnapshotPath { get; set; } = string.Empty;
    public DateTime ComparedUtc { get; set; } = DateTime.UtcNow;
    public int BaselineProcessCount { get; set; }
    public int CurrentProcessCount { get; set; }
    public IReadOnlyList<SnapshotComparisonFinding> Findings { get; set; } = Array.Empty<SnapshotComparisonFinding>();
}

public sealed class BaselineSnapshotMetadata
{
    public string BaselineId { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public string SnapshotPath { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public DateTime? CapturedUtc { get; set; }
    public string TrustNote { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class BaselinePolicyRule
{
    public string RuleId { get; set; } = Guid.NewGuid().ToString("N");
    public SnapshotComparisonArtifactKind ArtifactKind { get; set; } = SnapshotComparisonArtifactKind.Unknown;
    public string StableKey { get; set; } = string.Empty;
    public string Fingerprint { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class BaselinePolicyDocument
{
    public int SchemaVersion { get; set; } = 1;
    public IReadOnlyList<BaselineSnapshotMetadata> Baselines { get; set; } = Array.Empty<BaselineSnapshotMetadata>();
    public IReadOnlyList<BaselinePolicyRule> Rules { get; set; } = Array.Empty<BaselinePolicyRule>();
}
