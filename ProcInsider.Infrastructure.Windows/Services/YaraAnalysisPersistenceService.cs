using System.Security.Cryptography;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum YaraAnalysisPersistenceOutcome
{
    Created = 0,
    Unchanged = 1
}

public sealed record YaraAnalysisPersistenceRequest
{
    public string RequestId { get; init; } = string.Empty;

    public YaraScanAdmissionProfile AdmissionProfile { get; init; } = new();

    public YaraScanResult Result { get; init; } = new();
}

public sealed record YaraPersistedScan
{
    public string RequestId { get; init; } = string.Empty;

    public string AdmissionProfileId { get; init; } = string.Empty;

    public string AdmissionProfileVersion { get; init; } = string.Empty;

    public string ScannerArtifactHashSha256 { get; init; } = string.Empty;

    public int ScannerAdapterProtocolVersion { get; init; }

    public string RulesetManifestHashSha256 { get; init; } = string.Empty;

    public YaraScanResult Result { get; init; } = new();

    public string PayloadHashSha256 { get; init; } = string.Empty;
}

public sealed record YaraAnalysisPersistenceResult(
    YaraAnalysisPersistenceOutcome Outcome,
    string ScanId,
    string PayloadHashSha256);

internal static class YaraAnalysisPersistencePolicy
{
    private const int MaximumIdentityLength = 512;

    internal static YaraPersistedScan Normalize(YaraAnalysisPersistenceRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.RequestId) ||
            request.RequestId.Length > MaximumIdentityLength)
        {
            throw new InvalidDataException("The YARA request identity is missing or exceeds the persistence bound.");
        }

        var admission = YaraTrustAdmissionPolicy.Validate(request.AdmissionProfile);
        var result = YaraAnalysisContractPolicy.Validate(request.Result);
        if (!admission.Accepted || admission.Profile == null || admission.RulesetIdentity == null)
        {
            throw new InvalidDataException(
                $"The YARA admission profile failed persistence validation ({admission.Failure}).");
        }

        if (!result.Accepted || result.Result == null)
        {
            throw new InvalidDataException(
                $"The YARA result failed persistence validation ({result.Failure}).");
        }

        if (result.Result.Ruleset != admission.RulesetIdentity)
        {
            throw new InvalidDataException(
                "The YARA result scanner/ruleset identity does not match the admitted profile.");
        }

        if (result.Result.Matches.Any(match => match.StringMatches.Count != 0))
        {
            throw new InvalidDataException(
                "YARA string matches or excerpts cannot enter the normalized persistence schema.");
        }

        var canonicalResult = result.Result with
        {
            Target = result.Result.Target with
            {
                ContentHashSha256 = result.Result.Target.ContentHashSha256.ToUpperInvariant()
            },
            Ruleset = result.Result.Ruleset with
            {
                RulesetHashSha256 = result.Result.Ruleset.RulesetHashSha256.ToUpperInvariant()
            }
        };
        var canonical = new YaraPersistedScan
        {
            RequestId = request.RequestId,
            AdmissionProfileId = admission.Profile.ProfileId,
            AdmissionProfileVersion = admission.Profile.ProfileVersion,
            ScannerArtifactHashSha256 =
                admission.Profile.Scanner.ArtifactHashSha256.ToUpperInvariant(),
            ScannerAdapterProtocolVersion = admission.Profile.Scanner.AdapterProtocolVersion,
            RulesetManifestHashSha256 =
                admission.Profile.Ruleset.ManifestHashSha256.ToUpperInvariant(),
            Result = canonicalResult
        };
        return canonical with { PayloadHashSha256 = ComputePayloadHash(canonical) };
    }

    internal static string ComputePayloadHash(YaraPersistedScan scan)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            scan.RequestId,
            scan.AdmissionProfileId,
            scan.AdmissionProfileVersion,
            scan.ScannerArtifactHashSha256,
            scan.ScannerAdapterProtocolVersion,
            scan.RulesetManifestHashSha256,
            scan.Result
        });
        return Convert.ToHexString(SHA256.HashData(payload));
    }
}

/// <summary>
/// Focused derived-analysis writer. It can use only the store-owned transaction
/// context and never opens or selects a database independently.
/// </summary>
internal sealed class YaraAnalysisPersistenceService
{
    private readonly SqliteWriteTransactionContext _context;

    internal YaraAnalysisPersistenceService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    internal YaraAnalysisPersistenceResult Persist(
        YaraAnalysisPersistenceRequest request,
        CancellationToken cancellationToken)
    {
        var scan = YaraAnalysisPersistencePolicy.Normalize(request);
        cancellationToken.ThrowIfCancellationRequested();
        YaraAnalysisPersistenceResult? result = null;
        _context.Execute(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureSchemaPresent();
            ValidateSourceRun(scan.Result.Target);
            ValidateExactTarget(scan.Result.Target);
            var existing = ReadExisting(scan.RequestId, scan.Result.ScanId);
            if (existing != null)
            {
                if (string.Equals(existing.Value.RequestId, scan.RequestId, StringComparison.Ordinal) &&
                    string.Equals(existing.Value.ScanId, scan.Result.ScanId, StringComparison.Ordinal) &&
                    string.Equals(existing.Value.PayloadHash, scan.PayloadHashSha256, StringComparison.Ordinal))
                {
                    result = new YaraAnalysisPersistenceResult(
                        YaraAnalysisPersistenceOutcome.Unchanged,
                        scan.Result.ScanId,
                        scan.PayloadHashSha256);
                    return;
                }

                throw new InvalidDataException(
                    "The persisted YARA request or scan identity conflicts with a different payload.");
            }

            InsertScan(scan);
            InsertMatches(scan, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            result = new YaraAnalysisPersistenceResult(
                YaraAnalysisPersistenceOutcome.Created,
                scan.Result.ScanId,
                scan.PayloadHashSha256);
        });
        return result ?? throw new InvalidOperationException("The YARA persistence transaction produced no result.");
    }

    private void EnsureSchemaPresent()
    {
        using var command = _context.CreateCommand(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN " +
            "('YaraAnalysisScans','YaraAnalysisMatches','YaraAnalysisTags','YaraAnalysisMetadata');");
        if (Convert.ToInt32(command.ExecuteScalar()) != 4)
        {
            throw new InvalidDataException(
                "The cataloged YARA rebuildable-analysis schema is unavailable.");
        }
    }

    private void ValidateSourceRun(YaraScanTarget target)
    {
        using var command = _context.CreateCommand("""
            SELECT COUNT(*)
            FROM SourceRuns
            WHERE SourceRunId = $SourceRunId
              AND CaseId = $CaseId
              AND EvidenceSessionId = $EvidenceSessionId
              AND CaptureId = $CaptureId
              AND SourceIdentityId = $SourceIdentityId
              AND HostId = $HostId
              AND ExecutionRootId = $ExecutionRootId;
            """);
        AddScope(command, target);
        if (Convert.ToInt32(command.ExecuteScalar()) != 1)
        {
            throw new InvalidDataException(
                "The YARA result source run does not match the complete evidence scope.");
        }
    }

    private void ValidateExactTarget(YaraScanTarget target)
    {
        using var command = _context.CreateCommand(target.Kind switch
        {
            YaraScanTargetKind.FileArtifact => """
                SELECT COUNT(*)
                FROM Artifacts a
                WHERE a.ArtifactId = $ReferenceId
                  AND a.CaseId = $CaseId AND a.EvidenceSessionId = $EvidenceSessionId
                  AND a.CaptureId = $CaptureId AND a.SourceIdentityId = $SourceIdentityId
                  AND a.HostId = $HostId AND a.ExecutionRootId = $ExecutionRootId
                  AND a.SourceRunId = $SourceRunId
                  AND UPPER(a.Hash) = $ContentHash
                  AND EXISTS (SELECT 1 FROM ArtifactProperties p
                              WHERE p.ArtifactId = a.ArtifactId AND p.Name = 'Status'
                                AND p.Value = 'Imported')
                  AND EXISTS (SELECT 1 FROM ArtifactProperties p
                              WHERE p.ArtifactId = a.ArtifactId AND p.Name = 'FileSizeBytes'
                                AND CAST(p.Value AS INTEGER) = $LengthBytes);
                """,
            YaraScanTargetKind.MemoryDump => """
                SELECT COUNT(*)
                FROM MemoryDumps d
                WHERE d.DumpId = $ReferenceId
                  AND d.CaseId = $CaseId AND d.EvidenceSessionId = $EvidenceSessionId
                  AND d.CaptureId = $CaptureId AND d.SourceIdentityId = $SourceIdentityId
                  AND d.HostId = $HostId AND d.ExecutionRootId = $ExecutionRootId
                  AND d.SourceRunId = $SourceRunId AND d.Status = 'Captured'
                  AND UPPER(d.Sha256Hash) = $ContentHash
                  AND d.FileSizeBytes = $LengthBytes;
                """,
            YaraScanTargetKind.MemoryImageRegion => """
                SELECT COUNT(*)
                FROM MemoryImages m
                WHERE m.ImageId = $ReferenceId
                  AND m.CaseId = $CaseId AND m.EvidenceSessionId = $EvidenceSessionId
                  AND m.CaptureId = $CaptureId AND m.SourceIdentityId = $SourceIdentityId
                  AND m.HostId = $HostId AND m.ExecutionRootId = $ExecutionRootId
                  AND m.SourceRunId = $SourceRunId AND m.Status = 'Imported'
                  AND $OffsetBytes >= 0 AND $LengthBytes > 0
                  AND $OffsetBytes <= m.FileSizeBytes - $LengthBytes;
                """,
            _ => throw new InvalidDataException("The YARA persistence target kind is unsupported.")
        });
        AddScope(command, target);
        SqliteWriteTransactionContext.Add(command, "$ReferenceId", target.EvidenceReference.Id);
        SqliteWriteTransactionContext.Add(command, "$ContentHash", target.ContentHashSha256.ToUpperInvariant());
        SqliteWriteTransactionContext.Add(command, "$OffsetBytes", target.OffsetBytes);
        SqliteWriteTransactionContext.Add(command, "$LengthBytes", target.LengthBytes);
        if (Convert.ToInt32(command.ExecuteScalar()) != 1)
        {
            throw new InvalidDataException(
                "The YARA result no longer matches one exact current evidence target.");
        }
    }

    private (string RequestId, string ScanId, string PayloadHash)? ReadExisting(
        string requestId,
        string scanId)
    {
        using var command = _context.CreateCommand("""
            SELECT RequestId, ScanId, PayloadHashSha256
            FROM YaraAnalysisScans
            WHERE ScanId = $ScanId OR RequestId = $RequestId
            LIMIT 2;
            """);
        SqliteWriteTransactionContext.Add(command, "$ScanId", scanId);
        SqliteWriteTransactionContext.Add(command, "$RequestId", requestId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var value = (reader.GetString(0), reader.GetString(1), reader.GetString(2));
        if (reader.Read())
        {
            throw new InvalidDataException(
                "The YARA request and scan identities resolve to conflicting persisted rows.");
        }

        return value;
    }

    private void InsertScan(YaraPersistedScan scan)
    {
        var target = scan.Result.Target;
        using var command = _context.CreateCommand("""
            INSERT INTO YaraAnalysisScans (
                ScanId, RequestId, ResultSchemaVersion, Availability,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                ExecutionRootId, SourceRunId, TargetKind, EvidenceReferenceKind,
                EvidenceReferenceId, TargetOffsetBytes, TargetLengthBytes,
                TargetContentHashSha256, AdmissionProfileId, AdmissionProfileVersion,
                ScannerId, ScannerVersion, ScannerArtifactHashSha256,
                ScannerAdapterProtocolVersion, RulesetId, RulesetVersion,
                RulesetHashSha256, RulesetManifestHashSha256, RequestedUtc,
                CompletedUtc, IsTruncated, Diagnostic, PayloadHashSha256)
            VALUES (
                $ScanId, $RequestId, $ResultSchemaVersion, $Availability,
                $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId,
                $ExecutionRootId, $SourceRunId, $TargetKind, $EvidenceReferenceKind,
                $EvidenceReferenceId, $TargetOffsetBytes, $TargetLengthBytes,
                $TargetContentHashSha256, $AdmissionProfileId, $AdmissionProfileVersion,
                $ScannerId, $ScannerVersion, $ScannerArtifactHashSha256,
                $ScannerAdapterProtocolVersion, $RulesetId, $RulesetVersion,
                $RulesetHashSha256, $RulesetManifestHashSha256, $RequestedUtc,
                $CompletedUtc, $IsTruncated, $Diagnostic, $PayloadHashSha256);
            """);
        AddPersistedScope(command, target, scan.Result.ScanId);
        Add(command, "$RequestId", scan.RequestId);
        Add(command, "$ResultSchemaVersion", scan.Result.SchemaVersion);
        Add(command, "$Availability", (int)scan.Result.Availability);
        Add(command, "$TargetKind", (int)target.Kind);
        Add(command, "$EvidenceReferenceKind", (int)target.EvidenceReference.Kind);
        Add(command, "$EvidenceReferenceId", target.EvidenceReference.Id);
        Add(command, "$TargetOffsetBytes", target.OffsetBytes);
        Add(command, "$TargetLengthBytes", target.LengthBytes);
        Add(command, "$TargetContentHashSha256", target.ContentHashSha256);
        Add(command, "$AdmissionProfileId", scan.AdmissionProfileId);
        Add(command, "$AdmissionProfileVersion", scan.AdmissionProfileVersion);
        Add(command, "$ScannerId", scan.Result.Ruleset.ScannerId);
        Add(command, "$ScannerVersion", scan.Result.Ruleset.ScannerVersion);
        Add(command, "$ScannerArtifactHashSha256", scan.ScannerArtifactHashSha256);
        Add(command, "$ScannerAdapterProtocolVersion", scan.ScannerAdapterProtocolVersion);
        Add(command, "$RulesetId", scan.Result.Ruleset.RulesetId);
        Add(command, "$RulesetVersion", scan.Result.Ruleset.RulesetVersion);
        Add(command, "$RulesetHashSha256", scan.Result.Ruleset.RulesetHashSha256);
        Add(command, "$RulesetManifestHashSha256", scan.RulesetManifestHashSha256);
        Add(command, "$RequestedUtc", scan.Result.RequestedUtc);
        Add(command, "$CompletedUtc", scan.Result.CompletedUtc);
        Add(command, "$IsTruncated", scan.Result.IsTruncated ? 1 : 0);
        Add(command, "$Diagnostic", scan.Result.Diagnostic);
        Add(command, "$PayloadHashSha256", scan.PayloadHashSha256);
        command.ExecuteNonQuery();
    }

    private void InsertMatches(YaraPersistedScan scan, CancellationToken cancellationToken)
    {
        var target = scan.Result.Target;
        for (var matchOrder = 0; matchOrder < scan.Result.Matches.Count; matchOrder++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var match = scan.Result.Matches[matchOrder];
            using (var command = _context.CreateCommand("""
                       INSERT INTO YaraAnalysisMatches (
                           ScanId, MatchId, MatchOrder, CaseId, EvidenceSessionId,
                           CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                           SourceRunId, RuleNamespace, RuleId)
                       VALUES (
                           $ScanId, $MatchId, $MatchOrder, $CaseId, $EvidenceSessionId,
                           $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                           $SourceRunId, $RuleNamespace, $RuleId);
                       """))
            {
                AddPersistedScope(command, target, scan.Result.ScanId);
                Add(command, "$MatchId", match.MatchId);
                Add(command, "$MatchOrder", matchOrder);
                Add(command, "$RuleNamespace", match.RuleNamespace);
                Add(command, "$RuleId", match.RuleId);
                command.ExecuteNonQuery();
            }

            for (var tagOrder = 0; tagOrder < match.Tags.Count; tagOrder++)
            {
                using var command = _context.CreateCommand("""
                    INSERT INTO YaraAnalysisTags (
                        ScanId, MatchId, TagOrder, Tag, CaseId, EvidenceSessionId,
                        CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId)
                    VALUES (
                        $ScanId, $MatchId, $TagOrder, $Tag, $CaseId, $EvidenceSessionId,
                        $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId);
                    """);
                AddPersistedScope(command, target, scan.Result.ScanId);
                Add(command, "$MatchId", match.MatchId);
                Add(command, "$TagOrder", tagOrder);
                Add(command, "$Tag", match.Tags[tagOrder]);
                command.ExecuteNonQuery();
            }

            for (var metadataOrder = 0; metadataOrder < match.Metadata.Count; metadataOrder++)
            {
                using var command = _context.CreateCommand("""
                    INSERT INTO YaraAnalysisMetadata (
                        ScanId, MatchId, MetadataOrder, MetadataKey, MetadataValue,
                        CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                        HostId, ExecutionRootId, SourceRunId)
                    VALUES (
                        $ScanId, $MatchId, $MetadataOrder, $MetadataKey, $MetadataValue,
                        $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                        $HostId, $ExecutionRootId, $SourceRunId);
                    """);
                AddPersistedScope(command, target, scan.Result.ScanId);
                Add(command, "$MatchId", match.MatchId);
                Add(command, "$MetadataOrder", metadataOrder);
                Add(command, "$MetadataKey", match.Metadata[metadataOrder].Key);
                Add(command, "$MetadataValue", match.Metadata[metadataOrder].Value);
                command.ExecuteNonQuery();
            }
        }
    }

    private static void AddScope(Microsoft.Data.Sqlite.SqliteCommand command, YaraScanTarget target)
    {
        Add(command, "$CaseId", target.EvidenceIdentity.CaseId);
        Add(command, "$EvidenceSessionId", target.EvidenceIdentity.EvidenceSessionId);
        Add(command, "$CaptureId", target.EvidenceIdentity.CaptureId);
        Add(command, "$SourceIdentityId", target.EvidenceIdentity.SourceIdentityId);
        Add(command, "$HostId", target.EvidenceIdentity.HostId);
        Add(command, "$ExecutionRootId", target.EvidenceIdentity.ExecutionRootId);
        Add(command, "$SourceRunId", target.SourceRunId);
    }

    private static void AddPersistedScope(
        Microsoft.Data.Sqlite.SqliteCommand command,
        YaraScanTarget target,
        string scanId)
    {
        Add(command, "$ScanId", scanId);
        AddScope(command, target);
    }

    private static void Add(Microsoft.Data.Sqlite.SqliteCommand command, string name, object? value)
        => SqliteWriteTransactionContext.Add(command, name, value);
}
