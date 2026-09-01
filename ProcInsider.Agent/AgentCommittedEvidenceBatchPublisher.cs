using System.Threading.Channels;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Agent;

internal interface IAgentCommittedEvidenceBatchMaterializer
{
    /// <summary>
    /// Reads only the committed evidence represented by one durable ordered outbox entry.
    /// Repeating the same entry after a crash must return the identical immutable package.
    /// </summary>
    Task<InfrastructureEvidenceBatchPackage?> MaterializeAsync(
        InfrastructureEvidenceOutboxEntry outboxEntry,
        CancellationToken cancellationToken);
}

/// <summary>
/// Bridges the sole SQLite writer's transactional outbox to the separate file spool.
/// Notifications are wakeups only; the ordered SQLite outbox is the durable authority.
/// Start is explicit and publication-gated, so construction creates no path or worker.
/// </summary>
internal sealed class AgentCommittedEvidenceBatchPublisher : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly AgentStagingWriter _writer;
    private readonly AgentInfrastructureEvidenceSpool _spool;
    private readonly IAgentCommittedEvidenceBatchMaterializer _materializer;
    private readonly AgentInfrastructureEvidenceConnectivity _connectivity;
    private readonly Guid _ownerId = Guid.NewGuid();
    private readonly Channel<bool> _wakeups = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });
    private readonly CancellationTokenSource _stop = new();
    private Task? _worker;
    private AgentInfrastructureEvidenceOutbox? _outbox;
    private bool _started;

    public AgentCommittedEvidenceBatchPublisher(
        AgentStagingWriter writer,
        AgentInfrastructureEvidenceSpool spool,
        IAgentCommittedEvidenceBatchMaterializer materializer,
        AgentInfrastructureEvidenceConnectivity connectivity)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _materializer = materializer ?? throw new ArgumentNullException(nameof(materializer));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
    }

    public AgentInfrastructureEvidenceOutbox Outbox
    {
        get
        {
            lock (_gate)
            {
                return _outbox ?? throw new InvalidOperationException(
                    "The transactional evidence outbox is unavailable before explicit publisher start.");
            }
        }
    }

    public bool IsStarted
    {
        get
        {
            lock (_gate)
            {
                return _started && !_stop.IsCancellationRequested;
            }
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                throw new InvalidOperationException("The committed-evidence publisher is already active.");
            }

            // Enable first. A late or incompatible start must fail before creating a spool path.
            _outbox = _writer.EnableInfrastructureEvidenceOutbox(_ownerId);
            _spool.Initialize();
            _writer.DatabaseCommitted += OnDatabaseCommitted;
            _started = true;
            _worker = Task.Run(ProcessAsync);
            _wakeups.Writer.TryWrite(true);
        }
    }

    internal bool PublishCommitted(DatabaseChangedNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        if (notification.CommitGeneration <= 0 || notification.WriterInstanceId == Guid.Empty ||
            notification.LastCommittedAtUtc is not DateTime lastCommittedAtUtc ||
            lastCommittedAtUtc.Kind != DateTimeKind.Utc)
        {
            return false;
        }
        lock (_gate)
        {
            return _started && !_stop.IsCancellationRequested && _wakeups.Writer.TryWrite(true);
        }
    }

    private void OnDatabaseCommitted(DatabaseChangedNotification notification) => PublishCommitted(notification);

    private async Task ProcessAsync()
    {
        try
        {
            await foreach (var _ in _wakeups.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                while (!_stop.IsCancellationRequested)
                {
                    try
                    {
                        var outbox = Outbox;
                        var pending = outbox.List(
                            InfrastructureEvidenceOutboxState.Pending,
                            1).SingleOrDefault();
                        if (pending == null)
                        {
                            break;
                        }

                        var package = await _materializer.MaterializeAsync(pending, _stop.Token)
                            .ConfigureAwait(false);
                        if (package == null)
                        {
                            await RetryAsync(_stop.Token).ConfigureAwait(false);
                            break;
                        }

                        var result = _spool.Enqueue(package);
                        if (result.Accepted && result.Entry != null)
                        {
                            await outbox.BindPackageAsync(new InfrastructureEvidenceOutboxPackageBinding
                            {
                                OutboxId = pending.OutboxId,
                                BatchId = package.Manifest.BatchId,
                                ManifestSha256 = package.Manifest.ManifestSha256,
                                PackageSha256 = result.Entry.PackageSha256,
                                BoundAtUtc = DateTime.UtcNow
                            }, _stop.Token).ConfigureAwait(false);
                            continue;
                        }

                        if (result.Failure == InfrastructureEvidenceFailure.DuplicateConflict)
                        {
                            await outbox.QuarantineAsync(
                                pending.OutboxId,
                                result.ErrorCode,
                                DateTime.UtcNow,
                                _stop.Token).ConfigureAwait(false);
                            var conflictingPackage = _spool.ListPending().FirstOrDefault(entry =>
                                string.Equals(
                                    entry.Manifest.BatchId,
                                    package.Manifest.BatchId,
                                    StringComparison.Ordinal));
                            if (conflictingPackage != null)
                            {
                                _spool.Quarantine(conflictingPackage, result.ErrorCode);
                            }
                            _connectivity.RecordBackpressure(result.ErrorCode);
                            continue;
                        }

                        if (result.ErrorCode == "EvidenceSpoolQuotaBlocked")
                        {
                            _connectivity.RecordSpoolBlocked(result.ErrorCode);
                        }
                        else
                        {
                            _connectivity.RecordBackpressure(result.ErrorCode);
                        }
                        await RetryAsync(_stop.Token).ConfigureAwait(false);
                        break;
                    }
                    catch (OperationCanceledException) when (_stop.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
                    {
                        _connectivity.RecordBackpressure("CommittedEvidenceMaterializationFailed");
                        await RetryAsync(_stop.Token).ConfigureAwait(false);
                        break;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
    }

    private async Task RetryAsync(CancellationToken cancellationToken)
    {
        await Task.Delay(InfrastructureEvidenceInterchange.MinimumReconnectDelay, cancellationToken)
            .ConfigureAwait(false);
        _wakeups.Writer.TryWrite(true);
    }

    public async ValueTask DisposeAsync()
    {
        Task? worker;
        lock (_gate)
        {
            if (!_started)
            {
                _stop.Dispose();
                return;
            }
            _writer.DatabaseCommitted -= OnDatabaseCommitted;
            _started = false;
            _stop.Cancel();
            _wakeups.Writer.TryComplete();
            worker = _worker;
        }
        if (worker != null)
        {
            try
            {
                await worker.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        _stop.Dispose();
    }
}
