using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services.Forensics;

namespace ProcInsider.Agent;

/// <summary>Agent-owned finite Prefetch workflow. The reader supplies one held-handle byte snapshot and the parser never reopens its path.</summary>
internal sealed class AgentPrefetchAnalysisJobHandler(IPrefetchLocalReader reader, IForensicArtifactParser parser, IEvidenceSourcePublisher publisher) : IAgentJobHandler
{
    private readonly IPrefetchLocalReader _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    private readonly IForensicArtifactParser _parser = parser ?? throw new ArgumentNullException(nameof(parser));
    private readonly IEvidenceSourcePublisher _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var examined = 0;
        var parsed = 0; var partial = 0; var failed = 0; var unsupported = 0;
        var persisted = 0; var duplicates = 0; var reused = 0;
        var coverage = new List<object>();
        void RecordCompletion(string state) => context.SetSourceRunCompletion(state, JsonSerializer.Serialize(new { state, filesExamined = examined, coverage, parsed, partial, unsupported, failed, persisted, duplicates, reused, originalFilesRetained = false }));
        try { _reader.Read(read =>
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (read.IsCoverage)
            {
                partial++;
                coverage.Add(new { read.DiagnosticCode, read.Diagnostic });
                RecordCompletion("Partial");
                return;
            }
            var parse = read.Input == null
                ? new ForensicParseResult(ForensicParseStatus.NotAttempted, [], read.DiagnosticCode, read.Diagnostic)
                : _parser.Parse(read.Input, context.CancellationToken);
            if (parse.Status is ForensicParseStatus.Succeeded or ForensicParseStatus.Partial) parsed++;
            if (parse.Status == ForensicParseStatus.Partial) partial++;
            if (parse.Status == ForensicParseStatus.Unsupported) unsupported++;
            if (read.Status != ForensicReadStatus.Succeeded || parse.Status is ForensicParseStatus.Failed or ForensicParseStatus.Cancelled) failed++;
            var attempt = new ForensicReadAttempt
            {
                AttemptId = Guid.NewGuid().ToString("N"), Scope = context.Request.EvidenceIdentity,
                SourceRunId = context.SourceRunId, IngestionJobId = context.Request.JobId, SourcePath = read.SourcePath,
                PathSemantics = ForensicSourcePathSemantics.WindowsOrdinalIgnoreCase,
                ReadStartedUtc = read.ReadStartedUtc, ReadCompletedUtc = read.ReadCompletedUtc,
                SourceCreatedUtc = read.SourceCreatedUtc, SourceLastModifiedUtc = read.SourceLastModifiedUtc,
                InputByteCount = read.Input?.ByteCount, InputSha256 = read.Input?.Sha256,
                Consistency = read.Consistency, Status = read.Status, ParserStatus = parse.Status,
                DiagnosticCode = string.IsNullOrEmpty(read.DiagnosticCode) ? parse.DiagnosticCode : read.DiagnosticCode,
                Diagnostic = string.IsNullOrEmpty(read.Diagnostic) ? parse.Diagnostic : read.Diagnostic,
                Parser = _parser.Identity, Outputs = read.Consistency == ForensicReadConsistency.Stable ? parse.Outputs : []
            };
            EvidenceSourcePublishResult published;
            try
            {
                published = _publisher.PublishAsync(new EvidenceSourceEmissionBatch
                {
                    SourceRunId = context.SourceRunId, IngestionJobId = context.Request.JobId, Sequence = examined + 1, IsFinalBatch = false, ForensicReads = [attempt]
                }, context.CancellationToken).AsTask().GetAwaiter().GetResult();
            }
            catch (EvidenceSourcePublishException error)
            {
                examined++;
                failed++;
                persisted += error.PersistedRowCount;
                RecordCompletion("Failed");
                throw;
            }
            persisted += published.PersistedRowCount; duplicates += published.DuplicateRowCount; reused += published.ReusedResultCount;
            examined++;
            RecordCompletion("Partial");
        }, context.CancellationToken); }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { RecordCompletion("Cancelled"); throw; }
        catch { RecordCompletion("Failed"); throw; }
        var state = parsed == 0 && coverage.Count == 0 && failed > 0 ? "Failed" : failed == 0 && partial == 0 && unsupported == 0 ? "Complete" : "Partial";
        RecordCompletion(state);
        if (state == "Failed") throw new InvalidOperationException("Every actual Prefetch file attempt failed; inspect the persisted read receipts and source-run coverage.");
        await context.ReportProgressAsync(examined, examined, $"Prefetch {state}: {parsed:N0} parsed, {partial:N0} partial, {unsupported:N0} unsupported, {failed:N0} failed, {reused:N0} accepted reusable result(s).").ConfigureAwait(false);
    }
}
