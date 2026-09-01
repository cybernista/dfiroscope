using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface IDumpPeEvidenceWriteService
{
    void UpsertMemoryDump(MemoryDumpRecord memoryDump);
    void UpsertMemoryDumps(IEnumerable<MemoryDumpRecord> memoryDumps);
    void UpsertPeAnalysis(PeAnalysisRecord analysis);
    void UpsertPeAnalyses(IEnumerable<PeAnalysisRecord> analyses);
    void InsertAuthenticodeVerification(AuthenticodeVerificationRecord verification);
    void InsertAuthenticodeVerifications(IEnumerable<AuthenticodeVerificationRecord> verifications);
}

/// <summary>
/// Focused runtime process-dump and PE-analysis writer. The store facade owns
/// database selection, the connection, and transaction lifetime; this component
/// owns only family-specific SQL, binding, attachment, and derivation side effects.
/// </summary>
internal sealed class DumpPeEvidenceWriteService : IDumpPeEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal DumpPeEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void UpsertMemoryDump(MemoryDumpRecord memoryDump)
    {
        ArgumentNullException.ThrowIfNull(memoryDump);
        _context.Execute(() =>
        {
            using var command = CreateMemoryDumpUpsertCommand();
            WriteMemoryDumpCore(command, memoryDump);
        });
    }

    public void UpsertMemoryDumps(IEnumerable<MemoryDumpRecord> memoryDumps)
    {
        ArgumentNullException.ThrowIfNull(memoryDumps);
        var snapshot = memoryDumps.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateMemoryDumpUpsertCommand();
            command.Prepare();
            foreach (var memoryDump in snapshot)
            {
                ArgumentNullException.ThrowIfNull(memoryDump);
                WriteMemoryDumpCore(command, memoryDump);
            }
        });
    }

    public void UpsertPeAnalysis(PeAnalysisRecord analysis)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        _context.Execute(() =>
        {
            using var command = CreatePeAnalysisUpsertCommand();
            WritePeAnalysisCore(command, analysis);
        });
    }

    public void UpsertPeAnalyses(IEnumerable<PeAnalysisRecord> analyses)
    {
        ArgumentNullException.ThrowIfNull(analyses);
        var snapshot = analyses.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreatePeAnalysisUpsertCommand();
            command.Prepare();
            foreach (var analysis in snapshot)
            {
                ArgumentNullException.ThrowIfNull(analysis);
                WritePeAnalysisCore(command, analysis);
            }
        });
    }

    public void InsertAuthenticodeVerification(AuthenticodeVerificationRecord verification)
    {
        ArgumentNullException.ThrowIfNull(verification);
        _context.Execute(() =>
        {
            using var command = CreateAuthenticodeInsertCommand();
            WriteAuthenticodeVerificationCore(command, verification);
        });
    }

    public void InsertAuthenticodeVerifications(IEnumerable<AuthenticodeVerificationRecord> verifications)
    {
        ArgumentNullException.ThrowIfNull(verifications);
        var snapshot = verifications.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateAuthenticodeInsertCommand();
            command.Prepare();
            foreach (var verification in snapshot)
            {
                ArgumentNullException.ThrowIfNull(verification);
                WriteAuthenticodeVerificationCore(command, verification);
            }
        });
    }

    private void WriteMemoryDumpCore(SqliteCommand command, MemoryDumpRecord memoryDump)
    {
        var sourceId = _context.EnsureTelemetrySource(memoryDump.Source, "MemoryDump");
        var identity = _context.ResolveEvidenceIdentity(memoryDump, "MemoryDump", memoryDump.Source);
        ApplyEvidenceIdentity(memoryDump, identity);
        memoryDump.DumpId = NormalizeIdentifier(memoryDump.DumpId);
        var attachment = _context.PrepareProcessAttachedEvidence(
            memoryDump,
            EvidenceReferenceKind.MemoryDump,
            memoryDump.DumpId,
            memoryDump.ProcessId,
            memoryDump.ProcessGuid,
            processStartTimeUtc: null,
            memoryDump.ProcessName,
            memoryDump.RequestedUtc);

        Set(command, "$DumpId", memoryDump.DumpId);
        SetEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceId", sourceId);
        Set(command, "$ProcessEntityId", memoryDump.ProcessEntityId);
        Set(command, "$SourceRunId", EmptyToNull(memoryDump.SourceRunId));
        Set(command, "$IngestionJobId", memoryDump.IngestionJobId);
        Set(command, "$JobId", memoryDump.JobId?.ToString("D"));
        Set(command, "$ProcessKey", memoryDump.ProcessKey);
        Set(command, "$ProcessId", memoryDump.ProcessId);
        Set(command, "$ProcessGuid", memoryDump.ProcessGuid);
        Set(command, "$ProcessName", memoryDump.ProcessName);
        Set(command, "$DumpKind", memoryDump.DumpKind.ToString());
        Set(command, "$Status", memoryDump.Status.ToString());
        Set(command, "$RequestedUtc", memoryDump.RequestedUtc);
        Set(command, "$CompletedUtc", memoryDump.CompletedUtc);
        Set(command, "$OutputDirectory", memoryDump.OutputDirectory);
        Set(command, "$FilePath", memoryDump.FilePath);
        Set(command, "$FileSizeBytes", memoryDump.FileSizeBytes);
        Set(command, "$Sha256Hash", memoryDump.Sha256Hash);
        Set(command, "$ToolName", memoryDump.ToolName);
        Set(command, "$ErrorMessage", memoryDump.ErrorMessage);
        command.ExecuteNonQuery();

        _context.PersistProcessAttachedRelation(
            memoryDump,
            EvidenceReferenceKind.MemoryDump,
            memoryDump.DumpId,
            EvidenceRelationType.Created,
            attachment,
            memoryDump.RequestedUtc,
            memoryDump.CompletedUtc,
            memoryDump.DumpId,
            memoryDump.Status.ToString(),
            processIsSource: !string.IsNullOrWhiteSpace(memoryDump.ProcessEntityId));
    }

    private void WritePeAnalysisCore(SqliteCommand command, PeAnalysisRecord analysis)
    {
        var sourceId = _context.EnsureTelemetrySource(analysis.Source, "PEAnalysis");
        var identity = _context.ResolveEvidenceIdentity(analysis, "PEAnalysis", analysis.Source);
        ApplyEvidenceIdentity(analysis, identity);
        analysis.AnalysisId = NormalizeIdentifier(analysis.AnalysisId);
        var attachment = _context.PrepareProcessAttachedEvidence(
            analysis,
            EvidenceReferenceKind.PeAnalysis,
            analysis.AnalysisId,
            analysis.ProcessId,
            analysis.ProcessGuid,
            processStartTimeUtc: null,
            analysis.ProcessName,
            analysis.AnalyzedUtc);

        Set(command, "$AnalysisId", analysis.AnalysisId);
        SetEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceId", sourceId);
        Set(command, "$ProcessEntityId", analysis.ProcessEntityId);
        Set(command, "$SourceRunId", EmptyToNull(analysis.SourceRunId));
        Set(command, "$IngestionJobId", analysis.IngestionJobId);
        Set(command, "$ProcessKey", analysis.ProcessKey);
        Set(command, "$ProcessId", analysis.ProcessId);
        Set(command, "$ProcessGuid", analysis.ProcessGuid);
        Set(command, "$ProcessName", analysis.ProcessName);
        Set(command, "$SourceKind", analysis.SourceKind.ToString());
        Set(command, "$SourceArtifactId", analysis.SourceArtifactId);
        Set(command, "$FilePath", analysis.FilePath);
        Set(command, "$Status", analysis.Status.ToString());
        Set(command, "$AnalyzedUtc", analysis.AnalyzedUtc);
        Set(command, "$FileSizeBytes", analysis.FileSizeBytes);
        Set(command, "$FileLastWriteUtc", analysis.FileLastWriteUtc);
        Set(command, "$Sha256Hash", analysis.Sha256Hash);
        Set(command, "$Md5Hash", analysis.Md5Hash);
        Set(command, "$Machine", analysis.Machine);
        Set(command, "$Subsystem", analysis.Subsystem);
        Set(command, "$PeKind", analysis.PeKind);
        Set(command, "$LinkerTimestampUtc", analysis.LinkerTimestampUtc);
        Set(command, "$EntryPoint", analysis.EntryPoint);
        Set(command, "$ImageBase", analysis.ImageBase);
        Set(command, "$SectionCount", analysis.SectionCount);
        Set(command, "$ImportCount", analysis.ImportCount);
        Set(command, "$ExportCount", analysis.ExportCount);
        Set(command, "$PrintableStringCount", analysis.PrintableStringCount);
        Set(command, "$StringAnalysisStatus", analysis.StringAnalysisStatus.ToString());
        Set(command, "$SectionsJson", analysis.SectionsJson);
        Set(command, "$ImportsJson", analysis.ImportsJson);
        Set(command, "$ExportsJson", analysis.ExportsJson);
        Set(command, "$VersionInfoJson", analysis.VersionInfoJson);
        Set(command, "$StringSummaryJson", analysis.StringSummaryJson);
        Set(command, "$ErrorMessage", analysis.ErrorMessage);
        Set(command, "$PerformanceJson", analysis.PerformanceJson);
        command.ExecuteNonQuery();

        _context.PersistProcessAttachedRelation(
            analysis,
            EvidenceReferenceKind.PeAnalysis,
            analysis.AnalysisId,
            EvidenceRelationType.OwnedBy,
            attachment,
            analysis.AnalyzedUtc,
            rawInputId: string.IsNullOrWhiteSpace(analysis.SourceArtifactId)
                ? analysis.AnalysisId
                : analysis.SourceArtifactId,
            observationDiscriminator: analysis.StringAnalysisStatus.ToString());
        PersistPeAnalysisDerivationRelation(analysis);
    }

    private void WriteAuthenticodeVerificationCore(
        SqliteCommand command,
        AuthenticodeVerificationRecord verification)
    {
        var sourceId = _context.EnsureTelemetrySource(verification.Source, "AuthenticodeVerification");
        var identity = _context.ResolveEvidenceIdentity(
            verification,
            "AuthenticodeVerification",
            verification.Source);
        ApplyEvidenceIdentity(verification, identity);
        verification.VerificationId = NormalizeIdentifier(verification.VerificationId);
        var attachment = _context.PrepareProcessAttachedEvidence(
            verification,
            EvidenceReferenceKind.AuthenticodeVerification,
            verification.VerificationId,
            verification.ProcessId,
            verification.ProcessGuid,
            processStartTimeUtc: null,
            verification.ProcessName,
            verification.VerificationTimeUtc);

        Set(command, "$VerificationId", verification.VerificationId);
        Set(command, "$AnalysisId", verification.AnalysisId);
        SetEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceId", sourceId);
        Set(command, "$ProcessEntityId", verification.ProcessEntityId);
        Set(command, "$SourceRunId", EmptyToNull(verification.SourceRunId));
        Set(command, "$IngestionJobId", verification.IngestionJobId);
        Set(command, "$ProcessKey", verification.ProcessKey);
        Set(command, "$ProcessId", verification.ProcessId);
        Set(command, "$ProcessGuid", verification.ProcessGuid);
        Set(command, "$ProcessName", verification.ProcessName);
        Set(command, "$FilePath", verification.FilePath);
        Set(command, "$Sha256Hash", verification.Sha256Hash);
        Set(command, "$SignatureKind", verification.SignatureKind.ToString());
        Set(command, "$VerificationStatus", verification.VerificationStatus.ToString());
        Set(command, "$SignerSubject", verification.SignerSubject);
        Set(command, "$Publisher", verification.Publisher);
        Set(command, "$CertificateThumbprint", verification.CertificateThumbprint);
        Set(command, "$Issuer", verification.Issuer);
        Set(command, "$HasTimestamp", verification.HasTimestamp ? 1 : 0);
        Set(command, "$TimestampSubject", verification.TimestampSubject);
        Set(command, "$TimestampUtc", verification.TimestampUtc);
        Set(command, "$VerificationPolicy", verification.VerificationPolicy);
        Set(command, "$VerificationTimeUtc", verification.VerificationTimeUtc);
        Set(command, "$RevocationMode", verification.RevocationMode.ToString());
        Set(command, "$RevocationStatus", verification.RevocationStatus.ToString());
        Set(command, "$NativeStatusCode", verification.NativeStatusCode);
        Set(command, "$DiagnosticCode", verification.DiagnosticCode);
        Set(command, "$DiagnosticText", verification.DiagnosticText);
        if (command.ExecuteNonQuery() == 0)
        {
            return;
        }

        _context.PersistProcessAttachedRelation(
            verification,
            EvidenceReferenceKind.AuthenticodeVerification,
            verification.VerificationId,
            EvidenceRelationType.OwnedBy,
            attachment,
            verification.VerificationTimeUtc,
            rawInputId: verification.Sha256Hash,
            observationDiscriminator: verification.VerificationStatus.ToString());
        PersistAuthenticodeDerivationRelation(verification);
    }

    private SqliteCommand CreateMemoryDumpUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO MemoryDumps (
                DumpId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                JobId, ProcessKey, ProcessId, ProcessGuid, ProcessName,
                DumpKind, Status, RequestedUtc, CompletedUtc, OutputDirectory, FilePath,
                FileSizeBytes, Sha256Hash, ToolName, ErrorMessage)
            VALUES (
                $DumpId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $JobId, $ProcessKey, $ProcessId, $ProcessGuid, $ProcessName,
                $DumpKind, $Status, $RequestedUtc, $CompletedUtc, $OutputDirectory, $FilePath,
                $FileSizeBytes, $Sha256Hash, $ToolName, $ErrorMessage)
            ON CONFLICT(DumpId) DO UPDATE SET
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceId = excluded.SourceId,
                ProcessEntityId = excluded.ProcessEntityId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                JobId = excluded.JobId,
                ProcessKey = excluded.ProcessKey,
                ProcessId = excluded.ProcessId,
                ProcessGuid = excluded.ProcessGuid,
                ProcessName = excluded.ProcessName,
                DumpKind = excluded.DumpKind,
                Status = excluded.Status,
                RequestedUtc = excluded.RequestedUtc,
                CompletedUtc = excluded.CompletedUtc,
                OutputDirectory = excluded.OutputDirectory,
                FilePath = excluded.FilePath,
                FileSizeBytes = excluded.FileSizeBytes,
                Sha256Hash = excluded.Sha256Hash,
                ToolName = excluded.ToolName,
                ErrorMessage = excluded.ErrorMessage;
            """);
        AddParameters(command, new[]
        {
            "$DumpId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceId", "$ProcessEntityId", "$SourceRunId", "$IngestionJobId", "$JobId", "$ProcessKey", "$ProcessId",
            "$ProcessGuid", "$ProcessName", "$DumpKind", "$Status", "$RequestedUtc", "$CompletedUtc", "$OutputDirectory",
            "$FilePath", "$FileSizeBytes", "$Sha256Hash", "$ToolName", "$ErrorMessage"
        });
        return command;
    }

    private SqliteCommand CreatePeAnalysisUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO PeAnalyses (
                AnalysisId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                ProcessKey, ProcessId, ProcessGuid, ProcessName,
                SourceKind, SourceArtifactId, FilePath, Status, AnalyzedUtc, FileSizeBytes, FileLastWriteUtc,
                Sha256Hash, Md5Hash, Machine, Subsystem, PeKind, LinkerTimestampUtc,
                EntryPoint, ImageBase, SectionCount, ImportCount, ExportCount,
                PrintableStringCount, StringAnalysisStatus, SectionsJson, ImportsJson, ExportsJson,
                VersionInfoJson, StringSummaryJson, ErrorMessage, PerformanceJson)
            VALUES (
                $AnalysisId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $ProcessKey, $ProcessId, $ProcessGuid, $ProcessName,
                $SourceKind, $SourceArtifactId, $FilePath, $Status, $AnalyzedUtc, $FileSizeBytes, $FileLastWriteUtc,
                $Sha256Hash, $Md5Hash, $Machine, $Subsystem, $PeKind, $LinkerTimestampUtc,
                $EntryPoint, $ImageBase, $SectionCount, $ImportCount, $ExportCount,
                $PrintableStringCount, $StringAnalysisStatus, $SectionsJson, $ImportsJson, $ExportsJson,
                $VersionInfoJson, $StringSummaryJson, $ErrorMessage, $PerformanceJson)
            ON CONFLICT(AnalysisId) DO UPDATE SET
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceId = excluded.SourceId,
                ProcessEntityId = excluded.ProcessEntityId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                ProcessKey = excluded.ProcessKey,
                ProcessId = excluded.ProcessId,
                ProcessGuid = excluded.ProcessGuid,
                ProcessName = excluded.ProcessName,
                SourceKind = excluded.SourceKind,
                SourceArtifactId = excluded.SourceArtifactId,
                FilePath = excluded.FilePath,
                Status = excluded.Status,
                AnalyzedUtc = excluded.AnalyzedUtc,
                FileSizeBytes = excluded.FileSizeBytes,
                FileLastWriteUtc = excluded.FileLastWriteUtc,
                Sha256Hash = excluded.Sha256Hash,
                Md5Hash = excluded.Md5Hash,
                Machine = excluded.Machine,
                Subsystem = excluded.Subsystem,
                PeKind = excluded.PeKind,
                LinkerTimestampUtc = excluded.LinkerTimestampUtc,
                EntryPoint = excluded.EntryPoint,
                ImageBase = excluded.ImageBase,
                SectionCount = excluded.SectionCount,
                ImportCount = excluded.ImportCount,
                ExportCount = excluded.ExportCount,
                PrintableStringCount = excluded.PrintableStringCount,
                StringAnalysisStatus = excluded.StringAnalysisStatus,
                SectionsJson = excluded.SectionsJson,
                ImportsJson = excluded.ImportsJson,
                ExportsJson = excluded.ExportsJson,
                VersionInfoJson = excluded.VersionInfoJson,
                StringSummaryJson = excluded.StringSummaryJson,
                ErrorMessage = excluded.ErrorMessage,
                PerformanceJson = excluded.PerformanceJson;
            """);
        AddParameters(command, new[]
        {
            "$AnalysisId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceId", "$ProcessEntityId", "$SourceRunId", "$IngestionJobId", "$ProcessKey", "$ProcessId", "$ProcessGuid",
            "$ProcessName", "$SourceKind", "$SourceArtifactId", "$FilePath", "$Status", "$AnalyzedUtc", "$FileSizeBytes",
            "$FileLastWriteUtc", "$Sha256Hash", "$Md5Hash", "$Machine", "$Subsystem", "$PeKind", "$LinkerTimestampUtc",
            "$EntryPoint", "$ImageBase", "$SectionCount", "$ImportCount", "$ExportCount", "$PrintableStringCount",
            "$StringAnalysisStatus", "$SectionsJson", "$ImportsJson", "$ExportsJson", "$VersionInfoJson", "$StringSummaryJson",
            "$ErrorMessage", "$PerformanceJson"
        });
        return command;
    }

    private SqliteCommand CreateAuthenticodeInsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO AuthenticodeVerifications (
                VerificationId, AnalysisId,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                ProcessKey, ProcessId, ProcessGuid, ProcessName, FilePath, Sha256Hash,
                SignatureKind, VerificationStatus, SignerSubject, Publisher,
                CertificateThumbprint, Issuer, HasTimestamp, TimestampSubject, TimestampUtc,
                VerificationPolicy, VerificationTimeUtc, RevocationMode, RevocationStatus,
                NativeStatusCode, DiagnosticCode, DiagnosticText)
            VALUES (
                $VerificationId, $AnalysisId,
                $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $ProcessKey, $ProcessId, $ProcessGuid, $ProcessName, $FilePath, $Sha256Hash,
                $SignatureKind, $VerificationStatus, $SignerSubject, $Publisher,
                $CertificateThumbprint, $Issuer, $HasTimestamp, $TimestampSubject, $TimestampUtc,
                $VerificationPolicy, $VerificationTimeUtc, $RevocationMode, $RevocationStatus,
                $NativeStatusCode, $DiagnosticCode, $DiagnosticText)
            ON CONFLICT(VerificationId) DO NOTHING;
            """);
        AddParameters(command, new[]
        {
            "$VerificationId", "$AnalysisId", "$CaseId", "$EvidenceSessionId", "$CaptureId",
            "$SourceIdentityId", "$HostId", "$ExecutionRootId", "$SourceId", "$ProcessEntityId",
            "$SourceRunId", "$IngestionJobId", "$ProcessKey", "$ProcessId", "$ProcessGuid",
            "$ProcessName", "$FilePath", "$Sha256Hash", "$SignatureKind", "$VerificationStatus",
            "$SignerSubject", "$Publisher", "$CertificateThumbprint", "$Issuer", "$HasTimestamp",
            "$TimestampSubject", "$TimestampUtc", "$VerificationPolicy", "$VerificationTimeUtc",
            "$RevocationMode", "$RevocationStatus", "$NativeStatusCode", "$DiagnosticCode", "$DiagnosticText"
        });
        return command;
    }

    private void PersistPeAnalysisDerivationRelation(PeAnalysisRecord analysis)
    {
        var sourceArtifactId = string.IsNullOrWhiteSpace(analysis.SourceArtifactId)
            ? analysis.FilePath
            : analysis.SourceArtifactId;
        if (string.IsNullOrWhiteSpace(sourceArtifactId))
        {
            return;
        }

        var sourceKind = analysis.SourceKind == PeAnalysisSourceKind.MemoryDumpFile
            ? EvidenceReferenceKind.MemoryDump
            : EvidenceReferenceKind.FileArtifact;
        var sourceRun = string.IsNullOrWhiteSpace(analysis.SourceRunId) ? "legacy" : analysis.SourceRunId;
        var decisionKey = $"attachment:PeAnalysis:{analysis.AnalysisId}:{sourceRun}:{analysis.StringAnalysisStatus}:input";
        var relation = new EvidenceRelationService().CreateDecision(
            new EvidenceReference(sourceKind, sourceArtifactId),
            new EvidenceReference(EvidenceReferenceKind.PeAnalysis, analysis.AnalysisId),
            EvidenceRelationType.DerivedFrom,
            EvidenceCorrelationState.Asserted,
            analysis.SourceKind.ToString(),
            1.0,
            new EvidenceIdentity
            {
                CaseId = analysis.CaseId,
                EvidenceSessionId = analysis.EvidenceSessionId,
                CaptureId = analysis.CaptureId,
                SourceIdentityId = analysis.SourceIdentityId,
                HostId = analysis.HostId,
                ExecutionRootId = analysis.ExecutionRootId
            },
            "ProcessAttachedEvidenceWriter",
            decisionKey,
            analysis.AnalyzedUtc,
            analysis.SourceRunId,
            analysis.IngestionJobId,
            sourceArtifactId,
            resolverVersion: "process-attached-v1",
            candidateCount: 1,
            correlationDiagnostics: "PE analysis retains its source artifact by reference.");
        _context.PersistPeAnalysisDerivationRelation(relation);
    }

    private void PersistAuthenticodeDerivationRelation(AuthenticodeVerificationRecord verification)
    {
        if (string.IsNullOrWhiteSpace(verification.AnalysisId))
        {
            return;
        }

        var sourceRun = string.IsNullOrWhiteSpace(verification.SourceRunId) ? "legacy" : verification.SourceRunId;
        var relation = new EvidenceRelationService().CreateDecision(
            new EvidenceReference(EvidenceReferenceKind.PeAnalysis, verification.AnalysisId),
            new EvidenceReference(EvidenceReferenceKind.AuthenticodeVerification, verification.VerificationId),
            EvidenceRelationType.DerivedFrom,
            EvidenceCorrelationState.Asserted,
            "ExactAnalysisId",
            1.0,
            new EvidenceIdentity
            {
                CaseId = verification.CaseId,
                EvidenceSessionId = verification.EvidenceSessionId,
                CaptureId = verification.CaptureId,
                SourceIdentityId = verification.SourceIdentityId,
                HostId = verification.HostId,
                ExecutionRootId = verification.ExecutionRootId
            },
            "AuthenticodeEvidenceWriter",
            $"authenticode:{verification.VerificationId}:{sourceRun}:analysis",
            verification.VerificationTimeUtc,
            verification.SourceRunId,
            verification.IngestionJobId,
            verification.Sha256Hash,
            resolverVersion: "authenticode-v1",
            candidateCount: 1,
            correlationDiagnostics: "Authenticode verification retains the exact PE analysis and file hash it verified.");
        _context.PersistAuthenticodeDerivationRelation(relation);
    }

    private static void ApplyEvidenceIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static void SetEvidenceIdentityParameters(SqliteCommand command, EvidenceIdentity identity)
    {
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$CaptureId", identity.CaptureId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
    }

    private static void AddParameters(SqliteCommand command, IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            SqliteWriteTransactionContext.Add(command, name, null);
        }
    }

    private static string NormalizeIdentifier(string value)
        => string.IsNullOrWhiteSpace(value) ? Guid.NewGuid().ToString("N") : value;

    private static object? EmptyToNull(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static void Set(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = SqliteWriteTransactionContext.FormatDate(dateTime);
        }

        command.Parameters[name].Value = value ?? DBNull.Value;
    }
}
