using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed record ProcessEvidenceAttachmentResolution(
    EvidenceCorrelationState State,
    string Method,
    double Confidence,
    int CandidateCount,
    string Diagnostics);

/// <summary>
/// Store-owned capability passed to focused write components. It exposes only the
/// already-open connection/transaction and the shared provenance, relationship,
/// correlation, and search side effects that must remain atomic with evidence writes.
/// </summary>
internal sealed class SqliteWriteTransactionContext
{
    private readonly SqliteStagingStore _owner;

    internal SqliteWriteTransactionContext(SqliteStagingStore owner)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
    }

    internal void Execute(Action action) => _owner.ExecuteComponentWriteTransaction(action);

    internal SqliteCommand CreateCommand(string sql) => _owner.CreateComponentWriteCommand(sql);

    internal int? EnsureTelemetrySource(string displayName, string sourceType)
        => _owner.EnsureComponentTelemetrySource(displayName, sourceType);

    internal EvidenceIdentity ResolveEvidenceIdentity(
        IHasEvidenceIdentity record,
        string sourceType,
        string displayName)
        => _owner.ResolveComponentEvidenceIdentity(record, sourceType, displayName);

    internal ProcessEvidenceAttachmentResolution PrepareProcessAttachedEvidence(
        IHasProcessEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        int processId,
        string processGuid,
        DateTime? processStartTimeUtc,
        string processName,
        DateTime observedUtc)
        => _owner.PrepareComponentProcessAttachedEvidence(
            evidence,
            evidenceKind,
            evidenceId,
            processId,
            processGuid,
            processStartTimeUtc,
            processName,
            observedUtc);

    internal void PersistProcessAttachedRelation(
        IHasProcessEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        EvidenceRelationType relationType,
        ProcessEvidenceAttachmentResolution resolution,
        DateTime observedUtc,
        DateTime? observedToUtc = null,
        string rawInputId = "",
        string observationDiscriminator = "",
        bool processIsSource = false)
        => _owner.PersistComponentProcessAttachedRelation(
            evidence,
            evidenceKind,
            evidenceId,
            relationType,
            resolution,
            observedUtc,
            observedToUtc,
            rawInputId,
            observationDiscriminator,
            processIsSource);

    internal void PersistPeAnalysisDerivationRelation(EvidenceRelation relation)
        => _owner.PersistComponentPeAnalysisDerivationRelation(relation);

    internal void PersistAuthenticodeDerivationRelation(EvidenceRelation relation)
        => _owner.PersistComponentAuthenticodeDerivationRelation(relation);

    internal void ApplyNetworkEvidenceProvenance(IHasSourceRunEvidenceLink evidence)
        => _owner.ApplyComponentNetworkEvidenceProvenance(evidence);

    internal void ApplyFilesystemEvidenceProvenance(FilesystemArtifactRecord artifact)
        => _owner.ApplyComponentFilesystemEvidenceProvenance(artifact);

    internal void ApplySystemMemoryEvidenceProvenance(IHasSourceRunEvidenceLink evidence)
        => _owner.ApplyComponentSystemMemoryEvidenceProvenance(evidence);

    internal void PersistNetworkSourceRunRelation(
        IHasSourceRunEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        DateTime observedUtc,
        string rawInputId)
        => _owner.PersistComponentNetworkSourceRunRelation(
            evidence,
            evidenceKind,
            evidenceId,
            observedUtc,
            rawInputId);

    internal void PersistFilesystemSourceRunRelation(
        FilesystemArtifactRecord artifact,
        string artifactId,
        DateTime observedUtc,
        string rawInputId)
        => _owner.PersistComponentFilesystemSourceRunRelation(
            artifact,
            artifactId,
            observedUtc,
            rawInputId);

    internal void PersistSystemMemorySourceRunRelation(
        IHasSourceRunEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        DateTime observedUtc,
        string rawInputId)
        => _owner.PersistComponentSystemMemorySourceRunRelation(
            evidence,
            evidenceKind,
            evidenceId,
            observedUtc,
            rawInputId);

    internal void UpsertSearchIndex(SearchIndexRow row)
        => _owner.UpsertComponentSearchIndex(row);

    internal void ApplyPersistedEventCorrelationProvenance(
        EvidenceCorrelationInput input,
        long sequenceId)
        => _owner.ApplyComponentPersistedEventCorrelationProvenance(input, sequenceId);

    internal void ApplyPersistedZeekCorrelationProvenance(
        EvidenceCorrelationInput input,
        string artifactId)
        => _owner.ApplyComponentPersistedZeekCorrelationProvenance(input, artifactId);

    internal void ApplyPersistedMemoryProcessCorrelationProvenance(
        EvidenceCorrelationInput input,
        string artifactId)
        => _owner.ApplyComponentPersistedMemoryProcessCorrelationProvenance(input, artifactId);

    internal void UpsertEvidenceCorrelationInput(EvidenceCorrelationInput input)
        => _owner.UpsertComponentEvidenceCorrelationInput(input);

    internal void EnsureInitialCorrelationDecision(EvidenceCorrelationInput input)
        => _owner.EnsureComponentInitialCorrelationDecision(input);

    internal void RefreshProcessDerivedState(ProcessRecord process)
        => _owner.RefreshComponentProcessDerivedState(process);

    internal void RefreshProcessDerivedStates(IReadOnlyList<ProcessRecord> processes)
        => _owner.RefreshComponentProcessDerivedStates(processes);

    internal static void Add(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = FormatDate(dateTime);
        }

        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    internal static string FormatDate(DateTime value)
        => value.Kind == DateTimeKind.Utc
            ? value.ToString("O")
            : value.ToUniversalTime().ToString("O");
}
