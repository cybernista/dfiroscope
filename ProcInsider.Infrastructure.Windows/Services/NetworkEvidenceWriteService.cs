using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface INetworkEvidenceWriteService
{
    void UpsertNetworkCapture(NetworkCaptureRecord capture);
    void UpsertNetworkCaptures(IEnumerable<NetworkCaptureRecord> networkCaptures);
    void UpsertZeekNetworkArtifact(ZeekNetworkRecord artifact);
    void UpsertZeekNetworkArtifacts(IEnumerable<ZeekNetworkRecord> artifacts);
}

/// <summary>
/// Focused runtime network-capture and Zeek evidence writer. The store facade
/// owns database selection, the connection, and transaction lifetime; this
/// component owns only family-specific SQL, binding, lineage, search, and
/// initial correlation side effects.
/// </summary>
internal sealed class NetworkEvidenceWriteService : INetworkEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal NetworkEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void UpsertNetworkCapture(NetworkCaptureRecord capture)
    {
        ArgumentNullException.ThrowIfNull(capture);
        _context.Execute(() =>
        {
            using var command = CreateNetworkCaptureUpsertCommand();
            WriteNetworkCaptureCore(command, capture);
        });
    }

    public void UpsertNetworkCaptures(IEnumerable<NetworkCaptureRecord> networkCaptures)
    {
        ArgumentNullException.ThrowIfNull(networkCaptures);
        var snapshot = networkCaptures.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateNetworkCaptureUpsertCommand();
            command.Prepare();
            foreach (var capture in snapshot)
            {
                ArgumentNullException.ThrowIfNull(capture);
                WriteNetworkCaptureCore(command, capture);
            }
        });
    }

    public void UpsertZeekNetworkArtifact(ZeekNetworkRecord artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        _context.Execute(() =>
        {
            using var command = CreateZeekNetworkArtifactUpsertCommand();
            WriteZeekNetworkArtifactCore(command, artifact);
        });
    }

    public void UpsertZeekNetworkArtifacts(IEnumerable<ZeekNetworkRecord> artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        var snapshot = artifacts.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateZeekNetworkArtifactUpsertCommand();
            command.Prepare();
            foreach (var artifact in snapshot)
            {
                ArgumentNullException.ThrowIfNull(artifact);
                WriteZeekNetworkArtifactCore(command, artifact);
            }
        });
    }

    private void WriteNetworkCaptureCore(SqliteCommand command, NetworkCaptureRecord capture)
    {
        capture.CaptureId = NormalizeIdentifier(capture.CaptureId);
        var sourceId = _context.EnsureTelemetrySource(capture.Source, "NetworkCapture");
        var identity = _context.ResolveEvidenceIdentity(capture, "NetworkCapture", capture.Source);
        ApplyEvidenceIdentity(capture, identity);
        _context.ApplyNetworkEvidenceProvenance(capture);

        Set(command, "$CaptureId", capture.CaptureId);
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
        Set(command, "$SourceRunId", EmptyToNull(capture.SourceRunId));
        Set(command, "$IngestionJobId", capture.IngestionJobId);
        Set(command, "$SourceId", sourceId);
        Set(command, "$JobId", capture.JobId?.ToString("D"));
        Set(command, "$SegmentIndex", capture.SegmentIndex);
        Set(command, "$Status", capture.Status.ToString());
        Set(command, "$RequestedUtc", capture.RequestedUtc);
        Set(command, "$StartedUtc", capture.StartedUtc);
        Set(command, "$CompletedUtc", capture.CompletedUtc);
        Set(command, "$OutputDirectory", capture.OutputDirectory);
        Set(command, "$EtlFilePath", capture.EtlFilePath);
        Set(command, "$FilePath", capture.FilePath);
        Set(command, "$FileSizeBytes", capture.FileSizeBytes);
        Set(command, "$Sha256Hash", capture.Sha256Hash);
        Set(command, "$ToolName", capture.ToolName);
        Set(command, "$CaptureSource", capture.CaptureSource);
        Set(command, "$FilterDescription", capture.FilterDescription);
        Set(command, "$ErrorMessage", capture.ErrorMessage);
        command.ExecuteNonQuery();

        _context.PersistNetworkSourceRunRelation(
            capture,
            EvidenceReferenceKind.Capture,
            capture.CaptureId,
            capture.RequestedUtc,
            capture.Sha256Hash);
        _context.UpsertSearchIndex(CreateNetworkCaptureSearchIndexRow(capture));
    }

    private void WriteZeekNetworkArtifactCore(SqliteCommand command, ZeekNetworkRecord artifact)
    {
        artifact.ArtifactId = NormalizeIdentifier(artifact.ArtifactId);
        var sourceId = _context.EnsureTelemetrySource(artifact.Source, "Zeek");
        var identity = _context.ResolveEvidenceIdentity(artifact, "Zeek", artifact.Source);
        ApplyEvidenceIdentity(artifact, identity);
        _context.ApplyNetworkEvidenceProvenance(artifact);

        Set(command, "$ArtifactId", artifact.ArtifactId);
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
        Set(command, "$SourceRunId", EmptyToNull(artifact.SourceRunId));
        Set(command, "$IngestionJobId", artifact.IngestionJobId);
        Set(command, "$SourceId", sourceId);
        Set(command, "$CaptureId", artifact.CaptureId);
        Set(command, "$JobId", artifact.JobId?.ToString("D"));
        Set(command, "$Status", artifact.Status.ToString());
        Set(command, "$TimestampUtc", artifact.TimestampUtc);
        Set(command, "$LogType", artifact.LogType);
        Set(command, "$ZeekUid", artifact.ZeekUid);
        Set(command, "$SourceIp", artifact.SourceIp);
        Set(command, "$SourcePort", artifact.SourcePort);
        Set(command, "$DestinationIp", artifact.DestinationIp);
        Set(command, "$DestinationPort", artifact.DestinationPort);
        Set(command, "$Protocol", artifact.Protocol);
        Set(command, "$Service", artifact.Service);
        Set(command, "$DnsQuery", artifact.DnsQuery);
        Set(command, "$HttpMethod", artifact.HttpMethod);
        Set(command, "$HttpHost", artifact.HttpHost);
        Set(command, "$HttpUri", artifact.HttpUri);
        Set(command, "$DurationSeconds", artifact.DurationSeconds);
        Set(command, "$OrigBytes", artifact.OrigBytes);
        Set(command, "$RespBytes", artifact.RespBytes);
        Set(command, "$OrigPackets", artifact.OrigPackets);
        Set(command, "$RespPackets", artifact.RespPackets);
        Set(command, "$OrigIpBytes", artifact.OrigIpBytes);
        Set(command, "$RespIpBytes", artifact.RespIpBytes);
        Set(command, "$ConnectionState", artifact.ConnectionState);
        Set(command, "$History", artifact.History);
        Set(command, "$ServerName", artifact.ServerName);
        Set(command, "$ClientProtocol", artifact.ClientProtocol);
        Set(command, "$TlsVersion", artifact.TlsVersion);
        Set(command, "$TlsCipher", artifact.TlsCipher);
        Set(command, "$TlsEstablished", artifact.TlsEstablished ? 1 : 0);
        Set(command, "$WeirdName", artifact.WeirdName);
        Set(command, "$WeirdAdditional", artifact.WeirdAdditional);
        Set(command, "$Summary", artifact.Summary);
        Set(command, "$ProcessKey", artifact.ProcessKey);
        Set(command, "$ProcessId", artifact.ProcessId);
        Set(command, "$ProcessName", artifact.ProcessName);
        Set(command, "$CorrelationMethod", artifact.CorrelationMethod);
        Set(command, "$CorrelationConfidence", artifact.CorrelationConfidence);
        Set(command, "$RawLogPath", artifact.RawLogPath);
        Set(command, "$RawLineNumber", artifact.RawLineNumber);
        Set(command, "$RawLineHash", artifact.RawLineHash);
        Set(command, "$RawText", artifact.RawText);
        Set(command, "$ErrorMessage", artifact.ErrorMessage);
        command.ExecuteNonQuery();

        _context.PersistNetworkSourceRunRelation(
            artifact,
            EvidenceReferenceKind.NetworkFlow,
            artifact.ArtifactId,
            artifact.TimestampUtc,
            artifact.RawLineHash);
        _context.UpsertSearchIndex(CreateZeekSearchIndexRow(artifact));
        var input = CreateZeekCorrelationInput(artifact);
        _context.ApplyPersistedZeekCorrelationProvenance(input, artifact.ArtifactId);
        _context.UpsertEvidenceCorrelationInput(input);
        _context.EnsureInitialCorrelationDecision(input);
    }

    private SqliteCommand CreateNetworkCaptureUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO NetworkCaptures (
                CaptureId, CaseId, EvidenceSessionId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                SourceId, JobId, SegmentIndex, Status, RequestedUtc, StartedUtc,
                CompletedUtc, OutputDirectory, EtlFilePath, FilePath, FileSizeBytes,
                Sha256Hash, ToolName, CaptureSource, FilterDescription, ErrorMessage)
            VALUES (
                $CaptureId, $CaseId, $EvidenceSessionId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId,
                $SourceId, $JobId, $SegmentIndex, $Status, $RequestedUtc, $StartedUtc,
                $CompletedUtc, $OutputDirectory, $EtlFilePath, $FilePath, $FileSizeBytes,
                $Sha256Hash, $ToolName, $CaptureSource, $FilterDescription, $ErrorMessage)
            ON CONFLICT(CaptureId) DO UPDATE SET
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                SourceId = excluded.SourceId,
                JobId = excluded.JobId,
                SegmentIndex = excluded.SegmentIndex,
                Status = excluded.Status,
                RequestedUtc = excluded.RequestedUtc,
                StartedUtc = excluded.StartedUtc,
                CompletedUtc = excluded.CompletedUtc,
                OutputDirectory = excluded.OutputDirectory,
                EtlFilePath = excluded.EtlFilePath,
                FilePath = excluded.FilePath,
                FileSizeBytes = excluded.FileSizeBytes,
                Sha256Hash = excluded.Sha256Hash,
                ToolName = excluded.ToolName,
                CaptureSource = excluded.CaptureSource,
                FilterDescription = excluded.FilterDescription,
                ErrorMessage = excluded.ErrorMessage;
            """);
        AddParameters(command, new[]
        {
            "$CaptureId", "$CaseId", "$EvidenceSessionId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceRunId", "$IngestionJobId", "$SourceId", "$JobId", "$SegmentIndex", "$Status", "$RequestedUtc",
            "$StartedUtc", "$CompletedUtc", "$OutputDirectory", "$EtlFilePath", "$FilePath", "$FileSizeBytes",
            "$Sha256Hash", "$ToolName", "$CaptureSource", "$FilterDescription", "$ErrorMessage"
        });
        return command;
    }

    private SqliteCommand CreateZeekNetworkArtifactUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO ZeekNetworkArtifacts (
                ArtifactId, CaseId, EvidenceSessionId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                SourceId, CaptureId, JobId, Status, TimestampUtc, LogType, ZeekUid,
                SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, Service, DnsQuery,
                HttpMethod, HttpHost, HttpUri, DurationSeconds, OrigBytes, RespBytes,
                OrigPackets, RespPackets, OrigIpBytes, RespIpBytes, ConnectionState, History,
                ServerName, ClientProtocol, TlsVersion, TlsCipher, TlsEstablished,
                WeirdName, WeirdAdditional, Summary, ProcessKey,
                ProcessId, ProcessName, CorrelationMethod, CorrelationConfidence, RawLogPath,
                RawLineNumber, RawLineHash, RawText, ErrorMessage)
            VALUES (
                $ArtifactId, $CaseId, $EvidenceSessionId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId,
                $SourceId, $CaptureId, $JobId, $Status, $TimestampUtc, $LogType, $ZeekUid,
                $SourceIp, $SourcePort, $DestinationIp, $DestinationPort, $Protocol, $Service, $DnsQuery,
                $HttpMethod, $HttpHost, $HttpUri, $DurationSeconds, $OrigBytes, $RespBytes,
                $OrigPackets, $RespPackets, $OrigIpBytes, $RespIpBytes, $ConnectionState, $History,
                $ServerName, $ClientProtocol, $TlsVersion, $TlsCipher, $TlsEstablished,
                $WeirdName, $WeirdAdditional, $Summary, $ProcessKey,
                $ProcessId, $ProcessName, $CorrelationMethod, $CorrelationConfidence, $RawLogPath,
                $RawLineNumber, $RawLineHash, $RawText, $ErrorMessage)
            ON CONFLICT(ArtifactId) DO UPDATE SET
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                SourceId = excluded.SourceId,
                CaptureId = excluded.CaptureId,
                JobId = excluded.JobId,
                Status = excluded.Status,
                TimestampUtc = excluded.TimestampUtc,
                LogType = excluded.LogType,
                ZeekUid = excluded.ZeekUid,
                SourceIp = excluded.SourceIp,
                SourcePort = excluded.SourcePort,
                DestinationIp = excluded.DestinationIp,
                DestinationPort = excluded.DestinationPort,
                Protocol = excluded.Protocol,
                Service = excluded.Service,
                DnsQuery = excluded.DnsQuery,
                HttpMethod = excluded.HttpMethod,
                HttpHost = excluded.HttpHost,
                HttpUri = excluded.HttpUri,
                DurationSeconds = excluded.DurationSeconds,
                OrigBytes = excluded.OrigBytes,
                RespBytes = excluded.RespBytes,
                OrigPackets = excluded.OrigPackets,
                RespPackets = excluded.RespPackets,
                OrigIpBytes = excluded.OrigIpBytes,
                RespIpBytes = excluded.RespIpBytes,
                ConnectionState = excluded.ConnectionState,
                History = excluded.History,
                ServerName = excluded.ServerName,
                ClientProtocol = excluded.ClientProtocol,
                TlsVersion = excluded.TlsVersion,
                TlsCipher = excluded.TlsCipher,
                TlsEstablished = excluded.TlsEstablished,
                WeirdName = excluded.WeirdName,
                WeirdAdditional = excluded.WeirdAdditional,
                Summary = excluded.Summary,
                ProcessKey = excluded.ProcessKey,
                ProcessId = excluded.ProcessId,
                ProcessName = excluded.ProcessName,
                CorrelationMethod = excluded.CorrelationMethod,
                CorrelationConfidence = excluded.CorrelationConfidence,
                RawLogPath = excluded.RawLogPath,
                RawLineNumber = excluded.RawLineNumber,
                RawLineHash = excluded.RawLineHash,
                RawText = excluded.RawText,
                ErrorMessage = excluded.ErrorMessage;
            """);
        AddParameters(command, new[]
        {
            "$ArtifactId", "$CaseId", "$EvidenceSessionId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceRunId", "$IngestionJobId", "$SourceId", "$CaptureId", "$JobId", "$Status", "$TimestampUtc",
            "$LogType", "$ZeekUid", "$SourceIp", "$SourcePort", "$DestinationIp", "$DestinationPort", "$Protocol",
            "$Service", "$DnsQuery", "$HttpMethod", "$HttpHost", "$HttpUri", "$DurationSeconds", "$OrigBytes",
            "$RespBytes", "$OrigPackets", "$RespPackets", "$OrigIpBytes", "$RespIpBytes", "$ConnectionState",
            "$History", "$ServerName", "$ClientProtocol", "$TlsVersion", "$TlsCipher", "$TlsEstablished", "$WeirdName",
            "$WeirdAdditional", "$Summary", "$ProcessKey", "$ProcessId", "$ProcessName", "$CorrelationMethod",
            "$CorrelationConfidence", "$RawLogPath", "$RawLineNumber", "$RawLineHash", "$RawText", "$ErrorMessage"
        });
        return command;
    }

    internal static SearchIndexRow CreateNetworkCaptureSearchIndexRow(NetworkCaptureRecord capture)
        => new SearchIndexRow
        {
            Kind = "NetworkCapture",
            RecordKey = capture.CaptureId,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(capture.CompletedUtc ?? capture.StartedUtc ?? capture.RequestedUtc),
            Source = capture.Source,
            Title = $"Network capture segment {capture.SegmentIndex}",
            Subtitle = $"{capture.FilePath} | {capture.Status}",
            StatusText = capture.Status.ToString(),
            PathText = string.Join(' ', new[] { capture.FilePath, capture.EtlFilePath, capture.OutputDirectory }.Where(value => !string.IsNullOrWhiteSpace(value))),
            Sha256Text = capture.Sha256Hash,
            TargetText = capture.CaptureId,
            SummaryText = $"{capture.ToolName} | {capture.CaptureSource} | {capture.FilterDescription}",
            DetailsText = string.Join(
                Environment.NewLine,
                new[] { capture.SourceRunId, capture.IngestionJobId, capture.ErrorMessage }
                    .Where(value => !string.IsNullOrWhiteSpace(value))),
            CategoryText = "Network",
            ActionText = "Capture"
        }.WithSearchText();

    internal static SearchIndexRow CreateZeekSearchIndexRow(ZeekNetworkRecord artifact)
        => new SearchIndexRow
        {
            Kind = "Zeek",
            RecordKey = artifact.ArtifactId,
            ProcessKey = artifact.ProcessKey,
            ProcessId = artifact.ProcessId > 0 ? artifact.ProcessId.ToString(CultureInfo.InvariantCulture) : string.Empty,
            ProcessName = artifact.ProcessName,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(artifact.TimestampUtc),
            Source = artifact.Source,
            Title = $"{artifact.LogType} | {artifact.Protocol} | {artifact.Service}".Trim(' ', '|'),
            Subtitle = artifact.Summary,
            StatusText = artifact.Status.ToString(),
            ProcessNameText = artifact.ProcessName,
            TargetText = BuildZeekTarget(artifact),
            SummaryText = artifact.Summary,
            DetailsText = string.Join(
                " ",
                new[]
                {
                    artifact.RawText,
                    artifact.SourceRunId,
                    artifact.IngestionJobId,
                    artifact.ServerName,
                    artifact.ClientProtocol,
                    artifact.TlsVersion,
                    artifact.TlsCipher,
                    artifact.WeirdName,
                    artifact.WeirdAdditional,
                    artifact.ConnectionState,
                    artifact.History
                }.Where(value => !string.IsNullOrWhiteSpace(value))),
            CategoryText = "Network",
            ActionText = string.IsNullOrWhiteSpace(artifact.DnsQuery) ? "Connect" : "DnsQuery"
        }.WithSearchText();

    private static EvidenceCorrelationInput CreateZeekCorrelationInput(ZeekNetworkRecord artifact)
        => new()
        {
            InputId = $"zeek:{artifact.ArtifactId}",
            EvidenceKind = EvidenceReferenceKind.NetworkFlow,
            EvidenceId = artifact.ArtifactId,
            EvidenceType = artifact.LogType,
            Source = artifact.Source,
            RelationType = EvidenceRelationType.CorrelatesWith,
            CaseId = artifact.CaseId,
            EvidenceSessionId = artifact.EvidenceSessionId,
            CaptureId = artifact.CaptureId,
            SourceIdentityId = artifact.SourceIdentityId,
            HostId = artifact.HostId,
            ExecutionRootId = artifact.ExecutionRootId,
            IngestionJobId = artifact.JobId?.ToString("D") ?? string.Empty,
            RawInputId = artifact.RawLineHash,
            ProcessId = artifact.ProcessId,
            ProcessName = artifact.ProcessName,
            SourceNativeId = artifact.ProcessKey,
            SourceEndpoint = FormatEndpoint(artifact.SourceIp, artifact.SourcePort),
            DestinationEndpoint = FormatEndpoint(artifact.DestinationIp, artifact.DestinationPort),
            ObservedUtc = artifact.TimestampUtc,
            CreatedUtc = artifact.TimestampUtc
        };

    private static string BuildZeekTarget(ZeekNetworkRecord artifact)
    {
        var destination = string.IsNullOrWhiteSpace(artifact.DestinationIp)
            ? string.Empty
            : artifact.DestinationPort > 0
                ? $"{artifact.DestinationIp}:{artifact.DestinationPort}"
                : artifact.DestinationIp;
        return string.Join(" ", new[]
        {
            artifact.ZeekUid,
            artifact.SourceIp,
            destination,
            artifact.DnsQuery,
            artifact.HttpHost,
            artifact.HttpUri,
            artifact.Service,
            artifact.ServerName,
            artifact.ClientProtocol,
            artifact.WeirdName
        }.Where(value => !string.IsNullOrWhiteSpace(value)));
    }

    private static string FormatEndpoint(string address, int port)
        => string.IsNullOrWhiteSpace(address)
            ? string.Empty
            : port > 0 ? $"{address}:{port}" : address;

    private static void ApplyEvidenceIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
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
