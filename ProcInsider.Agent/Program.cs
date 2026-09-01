using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

internal static class Program
{
    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        AgentOptions options;
        try
        {
            options = AgentOptions.Parse(args);
        }
        catch (ArgumentException ex)
        {
            ConsoleMode.EnableIfRequested(foreground: true);
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine();
            Console.Error.WriteLine(AgentOptions.GetHelpText());
            return 2;
        }

        ConsoleMode.EnableIfRequested(
            options.Foreground || options.ShowHelp || options.CheckIpc || options.IpcStressTest);

        if (options.ShowHelp)
        {
            Console.WriteLine(AgentOptions.GetHelpText());
            return 0;
        }

        if (options.CheckIpc)
        {
            if (string.IsNullOrWhiteSpace(options.DatabasePath))
            {
                Console.Error.WriteLine("--check-ipc requires --database so the session-bound protected pairing can be selected.");
                return 2;
            }

            options = options.ResolveSessionPaths();
            var client = new AgentNamedPipeClient();
            client.BindSession(options.SessionPaths!);
            var response = await client.GetHealthAsync().ConfigureAwait(false);
            Console.WriteLine(JsonSerializer.Serialize(response, AgentIpcJson.JsonOptions));
            return response.Success ? 0 : 1;
        }

        if (options.HostMode == AgentHostMode.WindowsService)
        {
            return AgentWindowsServiceHost.Run(
                CurrentInfrastructureModeProfile.CreateAccessService(InfrastructureComponentKind.AgentService),
                options,
                AgentProcessRunner.RunAsync);
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            return await AgentProcessRunner.RunAsync(options, runtimeReady: null, cancellation.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{ProductIdentity.AgentDisplayName} failed: {ex.Message}");
            return 1;
        }
    }
}
