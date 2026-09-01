using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal static class AgentProcessRunner
{
    public static async Task<int> RunAsync(
        AgentOptions options,
        Action? runtimeReady,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!AgentInstanceGuard.TryAcquire(out var guard, out var guardFailure))
        {
            Console.Error.WriteLine(guardFailure?.Message ?? $"{ProductIdentity.AgentDisplayName} is already running on this system.");
            return 1;
        }

        using (guard)
        {
            if (options.HostMode == AgentHostMode.WindowsService)
            {
                AgentServiceStartupPolicy.ValidateOrThrow(options);
                var configuration = AgentInfrastructureConfigurationStartupPolicy.ValidateEnabledOrThrow(options);
                if (options.InfrastructureRuntimeCompositionFactory == null)
                {
                    throw new InvalidOperationException(
                        "The publication-authorized Agent Service has no protected Infrastructure runtime composition authority.");
                }
                options = options with { InfrastructureConfiguration = configuration };
            }

            options = options.ResolveSessionPaths();
            options = options with
            {
                Host = AgentHostRuntimeSnapshotFactory.Create(options)
            };

            using var log = AgentLog.Open(options.SessionPaths?.AgentLogPath);
            log.WriteLine(
                $"[{DateTimeOffset.Now:O}] Agent host identity: mode={options.Host.Mode}; " +
                $"account={options.Host.EffectiveAccountName}; sid={options.Host.EffectiveAccountSid}; " +
                $"localSystem={options.Host.IsLocalSystem}; pathScope={options.Host.PathScope}; version={options.Host.ProcessVersion}.");
            var host = new AgentHost(options, log);
            var exitCode = await host.RunAsync(cancellationToken, runtimeReady).ConfigureAwait(false);
            log.WriteLine($"[{DateTimeOffset.Now:O}] Agent runtime disposed; host mode={options.Host.Mode}; exitCode={exitCode}.");
            return exitCode;
        }
    }
}
