using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed partial class KnownFileServerLifecycleService : IKnownFileServerLifecycleService
{
    private const uint TokenQuery = 0x0008;
    private readonly INsrlControlClient _controlClient;
    private readonly string _expectedExecutablePath;
    private readonly string _currentUserSid;
    private readonly int _currentSessionId;
    private KnownFileServerConnection? _current;
    private bool _disposed;

    public KnownFileServerLifecycleService(
        INsrlControlClient controlClient,
        string expectedExecutablePath = "")
    {
        _controlClient = controlClient ?? throw new ArgumentNullException(nameof(controlClient));
        _expectedExecutablePath = Path.GetFullPath(string.IsNullOrWhiteSpace(expectedExecutablePath)
            ? Path.Combine(AppContext.BaseDirectory, "DFIRoscope.KnownFiles.Server.exe")
            : expectedExecutablePath);
        _currentUserSid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("The current Windows user SID is unavailable.");
        _currentSessionId = Process.GetCurrentProcess().SessionId;
    }

    public async Task<KnownFileServerLifecycleResult> ConnectAsync(
        KnownFileServerConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ValidateConfiguration(configuration);
        var candidates = ReadCandidates();
        var decision = KnownFileServerIdentityPolicy.Evaluate(
            candidates,
            _expectedExecutablePath,
            _currentUserSid,
            _currentSessionId);
        if (decision.Outcome == KnownFileServerLifecycleOutcome.NotRunning)
        {
            try
            {
                _ = await _controlClient.GetInfoAsync(configuration.Endpoint, cancellationToken).ConfigureAwait(false);
                return new KnownFileServerLifecycleResult(
                    KnownFileServerLifecycleOutcome.ForeignOrUnusable,
                    "A loopback endpoint responded without one exact eligible managed NSRL process; it was not adopted.");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new KnownFileServerLifecycleResult(
                    KnownFileServerLifecycleOutcome.TimedOut,
                    "The loopback endpoint did not answer within the bounded status timeout; no process was adopted.");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidDataException)
            {
                return decision;
            }
        }

        if (decision.Outcome != KnownFileServerLifecycleOutcome.Connected || decision.Connection is null)
        {
            _current = null;
            return decision;
        }

        try
        {
            var identity = decision.Connection.Process;
            var info = await _controlClient.GetInfoAsync(configuration.Endpoint, cancellationToken).ConfigureAwait(false);
            if (info.ProcessId != identity.ProcessId || !SameStart(info.ProcessStartUtc, identity.StartUtc))
            {
                return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.ForeignOrUnusable, "The loopback server identity does not match the exact eligible process.");
            }

            var status = await _controlClient.SendAuthenticatedAsync(
                configuration.ControlPipeName,
                info,
                new NsrlControlRequest { Command = NsrlControlCommand.Status },
                cancellationToken).ConfigureAwait(false);
            if (!status.Succeeded || status.Server is null)
            {
                return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Incompatible, "The current-user control endpoint rejected authenticated status.");
            }

            var rechecked = ReadIdentity(identity.ProcessId);
            if (rechecked is null || !SameIdentity(identity, rechecked))
            {
                return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.ForeignOrUnusable, "The managed NSRL process was replaced during authentication.");
            }

            var connection = new KnownFileServerConnection(
                identity,
                status.Server,
                configuration,
                _current?.StartedByViewer == true && SameIdentity(_current.Process, identity));
            _current = connection;
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Connected, "Connected to one exact authenticated managed NSRL server.", connection);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _current = null;
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.TimedOut, "Managed NSRL authentication timed out; no process was adopted.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or HttpRequestException)
        {
            _current = null;
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Incompatible, "Managed NSRL connection failed safely: " + Bound(ex.Message));
        }
    }

    public async Task<KnownFileServerLifecycleResult> StartAsync(
        KnownFileServerConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ValidateConfiguration(configuration);
        var existing = await ConnectAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (existing.IsConnected || existing.Outcome != KnownFileServerLifecycleOutcome.NotRunning)
        {
            return existing;
        }

        if (!File.Exists(_expectedExecutablePath))
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Failed, "The adjacent managed NSRL server executable is missing.");
        }

        if (!File.Exists(Path.GetFullPath(configuration.ValidationReceiptPath)))
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Failed, "The accepted-generation startup receipt is missing.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = _expectedExecutablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_expectedExecutablePath) ?? AppContext.BaseDirectory
        };
        startInfo.ArgumentList.Add("--catalog-root");
        startInfo.ArgumentList.Add(Path.GetFullPath(configuration.CatalogRoot));
        startInfo.ArgumentList.Add("--validation-receipt");
        startInfo.ArgumentList.Add(Path.GetFullPath(configuration.ValidationReceiptPath));
        startInfo.ArgumentList.Add("--address");
        startInfo.ArgumentList.Add(configuration.Endpoint.Host);
        startInfo.ArgumentList.Add("--port");
        startInfo.ArgumentList.Add(configuration.Endpoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        startInfo.ArgumentList.Add("--control-pipe");
        startInfo.ArgumentList.Add(configuration.ControlPipeName);
        var process = Process.Start(startInfo);
        if (process is null)
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Failed, "Windows did not return a managed NSRL process handle.");
        }

        var startedId = process.Id;
        process.Dispose();
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(200, cancellationToken).ConfigureAwait(false);
            var connected = await ConnectAsync(configuration, cancellationToken).ConfigureAwait(false);
            if (connected.IsConnected && connected.Connection?.Process.ProcessId == startedId)
            {
                _current = connected.Connection with { StartedByViewer = true };
                return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.StartedAndConnected, "Started and authenticated one exact current-user managed NSRL server.", _current);
            }

            if (connected.Outcome is KnownFileServerLifecycleOutcome.Ambiguous or KnownFileServerLifecycleOutcome.ForeignOrUnusable)
            {
                return connected;
            }
        }

        return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.TimedOut, "The exact started managed NSRL process did not become authenticated within 15 seconds; it was not force-stopped.");
    }

    public async Task<KnownFileServerLifecycleResult> StopAsync(
        KnownFileServerConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var connected = await ConnectAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (!connected.IsConnected || connected.Connection is null)
        {
            return connected;
        }

        var identity = connected.Connection.Process;
        var response = await _controlClient.SendAuthenticatedAsync(
            configuration.ControlPipeName,
            connected.Connection.Server,
            new NsrlControlRequest { Command = NsrlControlCommand.Shutdown },
            cancellationToken).ConfigureAwait(false);
        if (!response.Succeeded)
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Failed, "The authenticated managed NSRL server rejected graceful shutdown: " + Bound(response.Detail), connected.Connection);
        }

        try
        {
            using var process = Process.GetProcessById(identity.ProcessId);
            var rechecked = ReadIdentity(identity.ProcessId);
            if (rechecked is null || !SameIdentity(identity, rechecked))
            {
                return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.ForeignOrUnusable, "The managed NSRL process was replaced before exit observation; no process was terminated.");
            }

            await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
        }
        catch (ArgumentException)
        {
        }
        catch (TimeoutException)
        {
            return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.TimedOut, "Graceful shutdown was accepted, but the exact server remains running; no forced termination was attempted.", connected.Connection);
        }

        _current = null;
        return new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Stopped, "The exact authenticated managed NSRL server stopped gracefully.");
    }

    public void Dispose()
    {
        _disposed = true;
        _current = null;
        _controlClient.Dispose();
    }

    private IReadOnlyList<KnownFileServerProcessIdentity> ReadCandidates()
    {
        var result = new List<KnownFileServerProcessIdentity>();
        foreach (var process in Process.GetProcessesByName("DFIRoscope.KnownFiles.Server"))
        {
            using (process)
            {
                var identity = ReadIdentity(process);
                if (identity is not null)
                {
                    result.Add(identity);
                }
            }
        }

        return result;
    }

    private KnownFileServerProcessIdentity? ReadIdentity(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return ReadIdentity(process);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static KnownFileServerProcessIdentity? ReadIdentity(Process process)
    {
        try
        {
            var path = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(path) ||
                !OpenProcessToken(process.Handle, TokenQuery, out var token))
            {
                return null;
            }

            using (token)
            using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            {
                var sid = identity.User?.Value;
                return string.IsNullOrWhiteSpace(sid)
                    ? null
                    : new KnownFileServerProcessIdentity(
                        process.Id,
                        process.StartTime.ToUniversalTime(),
                        Path.GetFullPath(path),
                        sid,
                        process.SessionId);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static void ValidateConfiguration(KnownFileServerConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (string.IsNullOrWhiteSpace(configuration.CatalogRoot))
        {
            throw new InvalidDataException("An explicit reusable NSRL catalog root is required.");
        }

        if (string.IsNullOrWhiteSpace(configuration.ValidationReceiptPath))
        {
            throw new InvalidDataException("An explicit accepted-generation startup receipt is required.");
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration.CatalogRoot));
        var driveRoot = Path.GetPathRoot(root);
        if (driveRoot is not null && string.Equals(root, Path.TrimEndingDirectorySeparator(driveRoot), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("A drive root cannot be used as the managed NSRL catalog root.");
        }


        var receipt = Path.GetFullPath(configuration.ValidationReceiptPath);
        if (string.Equals(receipt, root, StringComparison.OrdinalIgnoreCase) ||
            receipt.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The accepted-generation startup receipt must remain outside the managed NSRL catalog root.");
        }

        if (!configuration.Endpoint.IsAbsoluteUri || configuration.Endpoint.Scheme != Uri.UriSchemeHttp ||
            !IPAddress.TryParse(configuration.Endpoint.Host, out var address) || !IPAddress.IsLoopback(address) ||
            !string.Equals(configuration.Endpoint.AbsolutePath, "/", StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(configuration.Endpoint.UserInfo) ||
            !string.IsNullOrEmpty(configuration.Endpoint.Query) ||
            !string.IsNullOrEmpty(configuration.Endpoint.Fragment))
        {
            throw new InvalidDataException("The managed NSRL server endpoint must be numeric HTTP loopback.");
        }
    }

    private static bool SameIdentity(KnownFileServerProcessIdentity left, KnownFileServerProcessIdentity right)
        => left.ProcessId == right.ProcessId &&
           SameStart(left.StartUtc, right.StartUtc) &&
           string.Equals(left.ExecutablePath, right.ExecutablePath, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(left.UserSid, right.UserSid, StringComparison.Ordinal) &&
           left.SessionId == right.SessionId;

    private static bool SameStart(DateTime left, DateTime right)
        => Math.Abs((left.ToUniversalTime() - right.ToUniversalTime()).TotalSeconds) <= 1;

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static string Bound(string value)
    {
        var text = value?.Trim() ?? string.Empty;
        return text.Length <= 512 ? text : text[..512];
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);
}
