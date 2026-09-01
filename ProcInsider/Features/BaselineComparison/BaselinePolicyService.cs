using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class BaselinePolicyService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private string _policyPath;

    public BaselinePolicyService(string policyPath)
    {
        _policyPath = Path.GetFullPath(policyPath);
    }

    public string PolicyPath => _policyPath;

    public void SetPolicyPath(string policyPath)
    {
        _policyPath = Path.GetFullPath(policyPath);
    }

    public BaselinePolicyDocument Load()
    {
        if (!File.Exists(_policyPath))
        {
            return new BaselinePolicyDocument();
        }

        var json = File.ReadAllText(_policyPath);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new BaselinePolicyDocument();
        }

        return JsonSerializer.Deserialize<BaselinePolicyDocument>(json, JsonOptions)
               ?? new BaselinePolicyDocument();
    }

    public void Save(BaselinePolicyDocument document)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_policyPath) ?? AppContext.BaseDirectory);
        File.WriteAllText(_policyPath, JsonSerializer.Serialize(document, JsonOptions));
    }

    public BaselinePolicyRule AcceptFinding(SnapshotComparisonFinding finding, string note)
    {
        var document = Load();
        var rules = document.Rules.ToList();
        var fingerprint = GetPolicyFingerprint(finding);
        var existing = rules.FirstOrDefault(rule =>
            rule.ArtifactKind == finding.ArtifactKind &&
            string.Equals(rule.StableKey, finding.StableKey, StringComparison.Ordinal) &&
            string.Equals(rule.Fingerprint, fingerprint, StringComparison.Ordinal));

        if (existing == null)
        {
            existing = new BaselinePolicyRule
            {
                ArtifactKind = finding.ArtifactKind,
                StableKey = finding.StableKey,
                Fingerprint = fingerprint,
                Title = finding.Title,
                Note = note,
                CreatedUtc = DateTime.UtcNow,
                UpdatedUtc = DateTime.UtcNow
            };
            rules.Add(existing);
        }
        else
        {
            existing.Title = finding.Title;
            existing.Note = note;
            existing.UpdatedUtc = DateTime.UtcNow;
        }

        Save(new BaselinePolicyDocument
        {
            SchemaVersion = document.SchemaVersion,
            Baselines = document.Baselines,
            Rules = rules
        });
        return existing;
    }

    public void SaveBaselineMetadata(BaselineSnapshotMetadata metadata)
    {
        var document = Load();
        var baselines = document.Baselines.ToList();
        metadata.SnapshotPath = Path.GetFullPath(metadata.SnapshotPath);
        metadata.UpdatedUtc = DateTime.UtcNow;
        if (metadata.CreatedUtc == default)
        {
            metadata.CreatedUtc = metadata.UpdatedUtc;
        }

        var existing = baselines.FirstOrDefault(baseline =>
            string.Equals(Path.GetFullPath(baseline.SnapshotPath), metadata.SnapshotPath, StringComparison.OrdinalIgnoreCase));
        if (existing == null)
        {
            baselines.Add(metadata);
        }
        else
        {
            existing.Name = metadata.Name;
            existing.HostId = metadata.HostId;
            existing.CapturedUtc = metadata.CapturedUtc;
            existing.TrustNote = metadata.TrustNote;
            existing.UpdatedUtc = metadata.UpdatedUtc;
        }

        Save(new BaselinePolicyDocument
        {
            SchemaVersion = document.SchemaVersion,
            Baselines = baselines,
            Rules = document.Rules
        });
    }

    public static BaselinePolicyRule? FindMatchingRule(
        BaselinePolicyDocument document,
        SnapshotComparisonArtifactKind artifactKind,
        string stableKey,
        string fingerprint)
    {
        return document.Rules.FirstOrDefault(rule =>
            rule.ArtifactKind == artifactKind &&
            string.Equals(rule.StableKey, stableKey, StringComparison.Ordinal) &&
            string.Equals(rule.Fingerprint, fingerprint, StringComparison.Ordinal));
    }

    private static string GetPolicyFingerprint(SnapshotComparisonFinding finding)
    {
        if (!string.IsNullOrWhiteSpace(finding.CurrentFingerprint))
        {
            return finding.CurrentFingerprint;
        }

        if (!string.IsNullOrWhiteSpace(finding.BaselineFingerprint))
        {
            return finding.BaselineFingerprint;
        }

        return finding.Fingerprint;
    }
}
