using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;
using System.Threading.Channels;

namespace ProcInsider.Agent;

internal sealed class AgentNetworkCaptureJobHandler : IAgentJobHandler
{
    private readonly NetworkCaptureService _captureService;
    private readonly NetworkCaptureEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;
    private readonly object _controlLock = new();
    private readonly Channel<NetworkCaptureControlRequest> _controlRequests =
        Channel.CreateUnbounded<NetworkCaptureControlRequest>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private Guid? _activeJobId;
    private bool _isPaused;

    public AgentNetworkCaptureJobHandler(
        NetworkCaptureService captureService,
        NetworkCaptureEvidenceSourceAdapter adapter,
        IEvidenceSourcePublisher publisher)
    {
        _captureService = captureService;
        _adapter = adapter;
        _publisher = publisher;
    }

    public Task<bool> RequestPauseAsync(Guid jobId, CancellationToken cancellationToken) =>
        RequestControlAsync(jobId, pause: true, cancellationToken);

    public Task<bool> RequestResumeAsync(Guid jobId, CancellationToken cancellationToken) =>
        RequestControlAsync(jobId, pause: false, cancellationToken);

    private async Task<bool> RequestControlAsync(
        Guid jobId,
        bool pause,
        CancellationToken cancellationToken)
    {
        NetworkCaptureControlRequest request;
        lock (_controlLock)
        {
            if (_activeJobId != jobId)
            {
                return false;
            }

            if (_isPaused == pause)
            {
                return true;
            }

            request = new NetworkCaptureControlRequest(pause);
            if (!_controlRequests.Writer.TryWrite(request))
            {
                return false;
            }
        }

        return await request.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<NetworkCaptureParameters>();
        var requestedUtc = DateTime.UtcNow;
        var segmentIndex = 1;
        var capture = CreateRecord(
            context,
            parameters,
            requestedUtc,
            NetworkCaptureStatus.Capturing,
            segmentIndex);
        await PublishAsync(context, capture, context.CancellationToken).ConfigureAwait(false);

        NetworkCaptureSession? session;
        try
        {
            session = await _captureService.StartCaptureAsync(
                context.Request.JobId,
                parameters.OutputDirectory,
                segmentIndex,
                context.CancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var failed = CreateFailedRecord(context, parameters, requestedUtc, ex.Message);
            await PublishAsync(context, failed, CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException(ex.Message, ex);
        }

        capture.StartedUtc = session.StartedUtc;
        capture.OutputDirectory = session.OutputDirectory;
        capture.EtlFilePath = session.EtlFilePath;
        capture.FilterDescription = BuildFilterDescription(session.LogFilePath);
        await PublishAsync(context, capture, CancellationToken.None).ConfigureAwait(false);
        await context.ReportProgressAsync(0, 1, $"Network capture running; ETL segment: {session.EtlFilePath}; diagnostic log: {session.LogFilePath}").ConfigureAwait(false);
        lock (_controlLock)
        {
            _activeJobId = context.Request.JobId;
            _isPaused = false;
        }

        try
        {
            while (true)
            {
                var control = await _controlRequests.Reader.ReadAsync(context.CancellationToken).ConfigureAwait(false);
                try
                {
                    if (control.Pause)
                    {
                        if (session == null)
                        {
                            control.Completion.TrySetResult(true);
                            continue;
                        }

                        var stopping = CreateStoppingRecord(
                            context,
                            parameters,
                            requestedUtc,
                            session,
                            segmentIndex);
                        await PublishAsync(context, stopping, CancellationToken.None).ConfigureAwait(false);
                        var result = await _captureService.StopCaptureAsync(session, CancellationToken.None).ConfigureAwait(false);
                        var completed = CreateCapturedRecord(
                            context,
                            parameters,
                            requestedUtc,
                            session.StartedUtc,
                            result,
                            segmentIndex);
                        await PublishAsync(context, completed, CancellationToken.None).ConfigureAwait(false);
                        session = null;
                        lock (_controlLock)
                        {
                            _isPaused = true;
                        }
                        await context.ReportProgressAsync(
                            segmentIndex,
                            -1,
                            "Network capture paused; finalized the current ETL segment and opened an explicit acquisition gap.",
                            CancellationToken.None).ConfigureAwait(false);
                        control.Completion.TrySetResult(true);
                        continue;
                    }

                    if (session != null)
                    {
                        control.Completion.TrySetResult(true);
                        continue;
                    }

                    segmentIndex++;
                    var resuming = CreateRecord(
                        context,
                        parameters,
                        requestedUtc,
                        NetworkCaptureStatus.Capturing,
                        segmentIndex);
                    await PublishAsync(context, resuming, CancellationToken.None).ConfigureAwait(false);
                    session = await _captureService.StartCaptureAsync(
                        context.Request.JobId,
                        parameters.OutputDirectory,
                        segmentIndex,
                        CancellationToken.None).ConfigureAwait(false);
                    resuming.StartedUtc = session.StartedUtc;
                    resuming.OutputDirectory = session.OutputDirectory;
                    resuming.EtlFilePath = session.EtlFilePath;
                    resuming.FilterDescription = BuildFilterDescription(session.LogFilePath);
                    await PublishAsync(context, resuming, CancellationToken.None).ConfigureAwait(false);
                    lock (_controlLock)
                    {
                        _isPaused = false;
                    }
                    await context.ReportProgressAsync(
                        segmentIndex,
                        -1,
                        $"Network capture resumed under the same job/source run; ETL segment: {session.EtlFilePath}",
                        CancellationToken.None).ConfigureAwait(false);
                    control.Completion.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    control.Completion.TrySetException(ex);
                }
            }
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            try
            {
                if (session != null)
                {
                    var stopping = CreateStoppingRecord(
                        context,
                        parameters,
                        requestedUtc,
                        session,
                        segmentIndex);
                    await PublishAsync(context, stopping, CancellationToken.None).ConfigureAwait(false);
                    await context.ReportProgressAsync(
                        0,
                        1,
                        $"Stopping Packet Monitor capture and finalizing ETL segment: {session.EtlFilePath}",
                        CancellationToken.None).ConfigureAwait(false);

                    var result = await _captureService.StopCaptureAsync(session, CancellationToken.None).ConfigureAwait(false);
                    var completed = CreateCapturedRecord(
                        context,
                        parameters,
                        requestedUtc,
                        session.StartedUtc,
                        result,
                        segmentIndex);
                    var completedResult = await PublishAsync(context, completed, CancellationToken.None).ConfigureAwait(false);
                    context.SetSourceRunCompletion(completedResult.State.ToString());
                    await context.ReportProgressAsync(
                        1,
                        1,
                        $"Network capture finalized: {result.FilePath}",
                        CancellationToken.None).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                var error = WithDiagnosticLog(ex.Message, session?.LogFilePath ?? string.Empty);
                var failed = CreateFailedRecord(context, parameters, requestedUtc, error);
                failed.StartedUtc = session?.StartedUtc;
                failed.OutputDirectory = session?.OutputDirectory ?? parameters.OutputDirectory;
                failed.EtlFilePath = session?.EtlFilePath ?? string.Empty;
                failed.FilterDescription = BuildFilterDescription(session?.LogFilePath ?? string.Empty);
                await PublishAsync(context, failed, CancellationToken.None).ConfigureAwait(false);
                throw new InvalidOperationException(error, ex);
            }

            return;
        }
        finally
        {
            lock (_controlLock)
            {
                _activeJobId = null;
                _isPaused = false;
            }

            while (_controlRequests.Reader.TryRead(out var pending))
            {
                pending.Completion.TrySetResult(false);
            }
        }
    }

    private async ValueTask<EvidenceSourceExecutionResult> PublishAsync(
        AgentJobContext context,
        NetworkCaptureRecord capture,
        CancellationToken cancellationToken)
    {
        var result = await _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                Payload = new NetworkCaptureEvidenceSourceInput { Captures = [capture] },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    NetworkCaptureEvidenceSourceAdapter.CaptureResultPrerequisite
                }
            },
            _publisher,
            null,
            cancellationToken).ConfigureAwait(false);
        if (result.State == EvidenceSourceCompletionState.Failed)
        {
            throw new InvalidOperationException("Network capture evidence adapter failed.");
        }

        return result;
    }

    private static NetworkCaptureRecord CreateRecord(
        AgentJobContext context,
        NetworkCaptureParameters parameters,
        DateTime requestedUtc,
        NetworkCaptureStatus status,
        int segmentIndex)
    {
        return new NetworkCaptureRecord
        {
            CaptureId = string.IsNullOrWhiteSpace(parameters.CaptureId)
                ? BuildCaptureId(context.Request.JobId, segmentIndex)
                : segmentIndex == 1
                    ? parameters.CaptureId
                    : $"{parameters.CaptureId}-segment-{segmentIndex:D4}",
            JobId = context.Request.JobId,
            SegmentIndex = segmentIndex,
            Status = status,
            RequestedUtc = requestedUtc,
            StartedUtc = status == NetworkCaptureStatus.Capturing ? DateTime.UtcNow : null,
            CompletedUtc = null,
            OutputDirectory = parameters.OutputDirectory,
            ToolName = "pktmon",
            CaptureSource = "LocalHost",
            FilterDescription = "Windows Packet Monitor capture; downstream TCP/PCAP analysis is staged by file reference.",
            Source = "AgentNetworkCapture"
        };
    }

    private static NetworkCaptureRecord CreateStoppingRecord(
        AgentJobContext context,
        NetworkCaptureParameters parameters,
        DateTime requestedUtc,
        NetworkCaptureSession session,
        int segmentIndex)
    {
        var record = CreateRecord(
            context,
            parameters,
            requestedUtc,
            NetworkCaptureStatus.Stopping,
            segmentIndex);
        record.StartedUtc = session.StartedUtc;
        record.OutputDirectory = session.OutputDirectory;
        record.EtlFilePath = session.EtlFilePath;
        record.FilterDescription = BuildFilterDescription(session.LogFilePath);
        return record;
    }

    private static NetworkCaptureRecord CreateCapturedRecord(
        AgentJobContext context,
        NetworkCaptureParameters parameters,
        DateTime requestedUtc,
        DateTime startedUtc,
        NetworkCaptureResult result,
        int segmentIndex)
    {
        var record = CreateRecord(
            context,
            parameters,
            requestedUtc,
            NetworkCaptureStatus.Captured,
            segmentIndex);
        record.StartedUtc = startedUtc;
        record.CompletedUtc = DateTime.UtcNow;
        record.OutputDirectory = result.OutputDirectory;
        record.EtlFilePath = result.EtlFilePath;
        record.FilePath = result.FilePath;
        record.FileSizeBytes = result.FileSizeBytes;
        record.Sha256Hash = result.Sha256Hash;
        record.ToolName = result.ToolName;
        record.FilterDescription = BuildFilterDescription(result.LogFilePath);
        return record;
    }

    private static NetworkCaptureRecord CreateFailedRecord(
        AgentJobContext context,
        NetworkCaptureParameters parameters,
        DateTime requestedUtc,
        string error)
    {
        var record = CreateRecord(context, parameters, requestedUtc, NetworkCaptureStatus.Failed, 1);
        record.CompletedUtc = DateTime.UtcNow;
        record.ErrorMessage = error;
        return record;
    }

    private static string BuildCaptureId(Guid jobId, int segmentIndex)
    {
        return $"{jobId:N}-segment-{segmentIndex:D4}";
    }

    private static string BuildFilterDescription(string logFilePath)
    {
        return string.IsNullOrWhiteSpace(logFilePath)
            ? "Windows Packet Monitor capture; downstream TCP/PCAP analysis is staged by file reference."
            : $"Windows Packet Monitor capture; downstream TCP/PCAP analysis is staged by file reference. Diagnostic log: {logFilePath}";
    }

    private static string WithDiagnosticLog(string error, string logFilePath)
    {
        if (string.IsNullOrWhiteSpace(logFilePath) ||
            error.Contains(logFilePath, StringComparison.OrdinalIgnoreCase))
        {
            return error;
        }

        return $"{error} Diagnostic log: {logFilePath}";
    }

    private sealed record NetworkCaptureParameters
    {
        public string CaptureId { get; init; } = string.Empty;

        public string OutputDirectory { get; init; } = string.Empty;
    }

    private sealed record NetworkCaptureControlRequest(bool Pause)
    {
        public TaskCompletionSource<bool> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
