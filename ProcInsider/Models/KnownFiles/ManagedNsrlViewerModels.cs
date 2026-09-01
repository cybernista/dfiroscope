using System.IO;

namespace ProcInsider.Models.KnownFiles;

public sealed record KnownFileServerConfiguration(
    string CatalogRoot,
    string ValidationReceiptPath,
    Uri Endpoint,
    string ControlPipeName);

public sealed record KnownFileServerProcessIdentity(
    int ProcessId,
    DateTime StartUtc,
    string ExecutablePath,
    string UserSid,
    int SessionId);

public enum KnownFileServerLifecycleOutcome
{
    Connected = 0,
    StartedAndConnected = 1,
    Stopped = 2,
    NotRunning = 3,
    ForeignOrUnusable = 4,
    Ambiguous = 5,
    Incompatible = 6,
    TimedOut = 7,
    Failed = 8
}

public sealed record KnownFileServerConnection(
    KnownFileServerProcessIdentity Process,
    NsrlServerInfo Server,
    KnownFileServerConfiguration Configuration,
    bool StartedByViewer);

public sealed record KnownFileServerLifecycleResult(
    KnownFileServerLifecycleOutcome Outcome,
    string Detail,
    KnownFileServerConnection? Connection = null)
{
    public bool IsConnected => Outcome is KnownFileServerLifecycleOutcome.Connected or KnownFileServerLifecycleOutcome.StartedAndConnected;
}

public static class KnownFileServerIdentityPolicy
{
    public static KnownFileServerLifecycleResult Evaluate(
        IReadOnlyList<KnownFileServerProcessIdentity> candidates,
        string expectedExecutablePath,
        string expectedUserSid,
        int expectedSessionId)
    {
        if (candidates.Count == 0)
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.NotRunning, "The managed NSRL server is not running.");
        }

        if (candidates.Count != 1)
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Ambiguous, "Multiple managed NSRL server process candidates are present; none was adopted.");
        }

        var candidate = candidates[0];
        if (!string.Equals(Path.GetFullPath(candidate.ExecutablePath), Path.GetFullPath(expectedExecutablePath), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(candidate.UserSid, expectedUserSid, StringComparison.Ordinal) ||
            candidate.SessionId != expectedSessionId ||
            candidate.ProcessId <= 0 ||
            candidate.StartUtc == default)
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.ForeignOrUnusable, "The running managed NSRL process does not match the expected path, current user, session, PID, or start identity.");
        }

        return new KnownFileServerLifecycleResult(
            KnownFileServerLifecycleOutcome.Connected,
            "The exact managed NSRL process identity is eligible for authenticated control.",
            new KnownFileServerConnection(
                candidate,
                new NsrlServerInfo(),
                new KnownFileServerConfiguration(string.Empty, string.Empty, new Uri(NsrlServerProtocol.DefaultEndpoint), NsrlServerProtocol.DefaultControlPipeName),
                false));
    }
}

public interface INsrlControlClient : IDisposable
{
    Task<NsrlServerInfo> GetInfoAsync(Uri endpoint, CancellationToken cancellationToken);

    Task<NsrlControlResponse> SendAuthenticatedAsync(
        string pipeName,
        NsrlServerInfo expectedServer,
        NsrlControlRequest request,
        CancellationToken cancellationToken);
}

public interface IKnownFileServerLifecycleService : IDisposable
{
    Task<KnownFileServerLifecycleResult> ConnectAsync(
        KnownFileServerConfiguration configuration,
        CancellationToken cancellationToken);

    Task<KnownFileServerLifecycleResult> StartAsync(
        KnownFileServerConfiguration configuration,
        CancellationToken cancellationToken);

    Task<KnownFileServerLifecycleResult> StopAsync(
        KnownFileServerConfiguration configuration,
        CancellationToken cancellationToken);
}
