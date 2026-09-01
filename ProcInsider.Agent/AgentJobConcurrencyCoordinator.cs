using System.Collections.Concurrent;
using System.Text.Json;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed class AgentJobConcurrencyCoordinator
{
    private readonly AgentWorkerOptions _options;
    private readonly AsyncExclusiveGate _databaseGate = new();
    private readonly SemaphoreSlim _enrichmentLimit;
    private readonly SemaphoreSlim _importLimit;
    private readonly SemaphoreSlim _processDumpLimit;
    private readonly SemaphoreSlim _zeekLimit;
    private readonly SemaphoreSlim _artifactImportLimit;
    private readonly SemaphoreSlim _volatilityLimit;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _resourceLocks = new(StringComparer.Ordinal);

    public AgentJobConcurrencyCoordinator(AgentWorkerOptions options)
    {
        _options = options.Normalize();
        _enrichmentLimit = new SemaphoreSlim(_options.MaxParallelEnrichmentJobs, _options.MaxParallelEnrichmentJobs);
        _importLimit = new SemaphoreSlim(_options.MaxParallelImportJobs, _options.MaxParallelImportJobs);
        _processDumpLimit = new SemaphoreSlim(_options.MaxParallelProcessDumpJobs, _options.MaxParallelProcessDumpJobs);
        _zeekLimit = new SemaphoreSlim(_options.MaxParallelZeekJobs, _options.MaxParallelZeekJobs);
        _artifactImportLimit = new SemaphoreSlim(_options.MaxParallelArtifactImportJobs, _options.MaxParallelArtifactImportJobs);
        _volatilityLimit = new SemaphoreSlim(_options.MaxParallelVolatilityJobs, _options.MaxParallelVolatilityJobs);
    }

    public async ValueTask<JobConcurrencyLease> AcquireAsync(AgentJobRequest request, CancellationToken cancellationToken)
    {
        var leases = new List<IDisposable>();
        try
        {
            leases.Add(IsDatabaseExclusive(request.JobKind)
                ? await _databaseGate.AcquireExclusiveAsync(cancellationToken).ConfigureAwait(false)
                : await _databaseGate.AcquireSharedAsync(cancellationToken).ConfigureAwait(false));

            switch (request.JobKind)
            {
                case JobKind.LiveCapture:
                    leases.Add(await AcquireResourceAsync("live-capture", cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.NetworkCapture:
                    leases.Add(await AcquireResourceAsync("network-capture", cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.ProcessMonitorCapture:
                    leases.Add(await AcquireResourceAsync("process-monitor-capture", cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.SqliteBenchmark:
                    leases.Add(await AcquireResourceAsync("sqlite-benchmark", cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.ModuleEnrichment:
                case JobKind.HandleEnrichment:
                case JobKind.PeAnalysis:
                    leases.Add(await AcquireSemaphoreAsync(_enrichmentLimit, cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.Import:
                    leases.Add(await AcquireSemaphoreAsync(_importLimit, cancellationToken).ConfigureAwait(false));
                    leases.Add(await AcquireResourceAsync("snapshot-import", cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.ProcessDump:
                    leases.Add(await AcquireSemaphoreAsync(_processDumpLimit, cancellationToken).ConfigureAwait(false));
                    leases.Add(await AcquireResourceAsync(BuildProcessDumpResourceKey(request), cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.ZeekAnalysis:
                    leases.Add(await AcquireSemaphoreAsync(_zeekLimit, cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.ArtifactImport:
                    leases.Add(await AcquireSemaphoreAsync(_artifactImportLimit, cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.ProcessMonitorImport:
                    leases.Add(await AcquireSemaphoreAsync(_importLimit, cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.MemoryImageImport:
                    leases.Add(await AcquireSemaphoreAsync(_importLimit, cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.MemoryAcquisition:
                    leases.Add(await AcquireResourceAsync("memory-acquisition", cancellationToken).ConfigureAwait(false));
                    break;
                case JobKind.VolatilityAnalysis:
                    leases.Add(await AcquireSemaphoreAsync(_volatilityLimit, cancellationToken).ConfigureAwait(false));
                    leases.Add(await AcquireResourceAsync(BuildMemoryImageResourceKey(request), cancellationToken).ConfigureAwait(false));
                    break;
            }

            return new JobConcurrencyLease(request.JobKind, leases);
        }
        catch
        {
            ReleaseAll(leases);
            throw;
        }
    }

    private static bool IsDatabaseExclusive(JobKind jobKind)
    {
        return jobKind is JobKind.Import;
    }

    private static async ValueTask<IDisposable> AcquireSemaphoreAsync(SemaphoreSlim semaphore, CancellationToken cancellationToken)
    {
        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new CallbackLease(() => semaphore.Release());
    }

    private async ValueTask<IDisposable> AcquireResourceAsync(string resourceKey, CancellationToken cancellationToken)
    {
        var semaphore = _resourceLocks.GetOrAdd(resourceKey, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new CallbackLease(() => semaphore.Release());
    }

    private static string BuildProcessDumpResourceKey(AgentJobRequest request)
    {
        var processKey = ReadStringParameter(request, "ProcessKey");
        return string.IsNullOrWhiteSpace(processKey)
            ? $"process-dump:{request.JobId:N}"
            : $"process-dump:{processKey}";
    }

    private static string BuildMemoryImageResourceKey(AgentJobRequest request)
    {
        var imageId = ReadStringParameter(request, "ImageId");
        return string.IsNullOrWhiteSpace(imageId)
            ? $"memory-image:{request.JobId:N}"
            : $"memory-image:{imageId}";
    }

    private static string ReadStringParameter(AgentJobRequest request, string name)
    {
        try
        {
            using var document = JsonDocument.Parse(request.ToParametersJson());
            return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? string.Empty
                : string.Empty;
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    private static void ReleaseAll(IReadOnlyList<IDisposable> leases)
    {
        for (var index = leases.Count - 1; index >= 0; index--)
        {
            leases[index].Dispose();
        }
    }

    private sealed class AsyncExclusiveGate
    {
        private readonly SemaphoreSlim _turnstile = new(1, 1);
        private readonly SemaphoreSlim _mutex = new(1, 1);
        private readonly SemaphoreSlim _resource = new(1, 1);
        private int _sharedCount;

        public async ValueTask<IDisposable> AcquireSharedAsync(CancellationToken cancellationToken)
        {
            await _turnstile.WaitAsync(cancellationToken).ConfigureAwait(false);
            _turnstile.Release();

            await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                _sharedCount++;
                if (_sharedCount == 1)
                {
                    await _resource.WaitAsync(cancellationToken).ConfigureAwait(false);
                }

                return new CallbackLease(ReleaseShared);
            }
            catch
            {
                _sharedCount--;
                throw;
            }
            finally
            {
                _mutex.Release();
            }
        }

        public async ValueTask<IDisposable> AcquireExclusiveAsync(CancellationToken cancellationToken)
        {
            await _turnstile.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await _resource.WaitAsync(cancellationToken).ConfigureAwait(false);
                return new CallbackLease(ReleaseExclusive);
            }
            catch
            {
                _turnstile.Release();
                throw;
            }
        }

        private void ReleaseShared()
        {
            _mutex.Wait();
            try
            {
                _sharedCount--;
                if (_sharedCount == 0)
                {
                    _resource.Release();
                }
            }
            finally
            {
                _mutex.Release();
            }
        }

        private void ReleaseExclusive()
        {
            _resource.Release();
            _turnstile.Release();
        }
    }

    private sealed class CallbackLease : IDisposable
    {
        private readonly Action _release;
        private int _disposed;

        public CallbackLease(Action release)
        {
            _release = release;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _release();
            }
        }
    }
}

internal sealed class JobConcurrencyLease : IDisposable
{
    private readonly IReadOnlyList<IDisposable> _leases;
    private int _disposed;

    public JobConcurrencyLease(JobKind jobKind, IReadOnlyList<IDisposable> leases)
    {
        JobKind = jobKind;
        _leases = leases;
    }

    public JobKind JobKind { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        for (var index = _leases.Count - 1; index >= 0; index--)
        {
            _leases[index].Dispose();
        }
    }
}
