using System.Text.Json;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.Cli;

internal static class ViewerCliApplication
{
    public const int EnvelopeSchemaVersion = 1;

    public static async Task<int> RunAsync(
        IReadOnlyList<string> args,
        IFeatureCatalog featureCatalog,
        ICliConsole console,
        ICliClock clock,
        Func<ICliCommandHandlerFactory> handlerFactory,
        CancellationToken cancellationToken = default,
        Func<ICliInterruptSource>? shellInterruptSourceFactory = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(featureCatalog);
        ArgumentNullException.ThrowIfNull(console);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(handlerFactory);

        var parsed = CliParser.Parse(args);
        var attemptedCommand = parsed.Invocation?.CommandName ?? CliParser.GetAttemptedCommand(args);
        if (!parsed.Success)
        {
            if (CliParser.IsKnownEntry(args) &&
                !featureCatalog.IsPublished(FeatureIds.CommandLine))
            {
                return Render(
                    attemptedCommand,
                    parsed.OutputMode,
                    CliCommandResult.Failed(
                        CliExitCode.Rejected,
                        "CommandLineNotPublished",
                        "The command-line surface is not published in this educational release."),
                    console,
                    clock.UtcNow);
            }

            return Render(
                attemptedCommand,
                parsed.OutputMode,
                CliCommandResult.Failed(
                    CliExitCode.Usage,
                    parsed.ErrorCode,
                    parsed.ErrorMessage,
                    text: $"{parsed.ErrorMessage}{Environment.NewLine}Run DFIRoscope.Live.exe --help for published syntax."),
                console,
                clock.UtcNow);
        }

        var invocation = parsed.Invocation!;
        if (!featureCatalog.IsPublished(FeatureIds.CommandLine))
        {
            return Render(
                invocation.CommandName,
                invocation.OutputMode,
                CliCommandResult.Failed(
                    CliExitCode.Rejected,
                    "CommandLineNotPublished",
                    "The command-line surface is not published in this educational release."),
                console,
                clock.UtcNow);
        }

        if (invocation.Kind == CliCommandKind.Shell)
        {
            try
            {
                using var factory = handlerFactory();
                using var interruptSource = shellInterruptSourceFactory?.Invoke() ??
                    new NullCliInterruptSource();
                using var shell = new ViewerCliShell(
                    featureCatalog,
                    console,
                    clock,
                    factory,
                    interruptSource);
                return await shell.RunAsync(invocation, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return Render(
                    invocation.CommandName,
                    invocation.OutputMode,
                    Canceled(),
                    console,
                    clock.UtcNow);
            }
            catch
            {
                return Render(
                    invocation.CommandName,
                    invocation.OutputMode,
                    CliCommandResult.Failed(
                        CliExitCode.Failure,
                        "InternalFailure",
                        "The shell failed internally."),
                    console,
                    clock.UtcNow);
            }
        }

        CliCommandResult result;
        var availabilityFailure = CliDispatcher.GetAvailabilityFailure(
            featureCatalog,
            invocation);
        if (availabilityFailure != null)
        {
            result = availabilityFailure;
        }
        else if (cancellationToken.IsCancellationRequested)
        {
            result = Canceled();
        }
        else
        {
            try
            {
                using var factory = handlerFactory();
                var dispatcher = new CliDispatcher(featureCatalog, factory);
                result = await ExecuteInvocationAsync(
                        invocation,
                        featureCatalog,
                        dispatcher,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch
            {
                result = InternalFailure();
            }
        }

        return Render(
            invocation.CommandName,
            invocation.OutputMode,
            result,
            console,
            clock.UtcNow);
    }

    internal static int Render(
        string command,
        CliOutputMode outputMode,
        CliCommandResult result,
        ICliConsole console,
        DateTime timestampUtc)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (outputMode == CliOutputMode.Json)
        {
            var envelope = new CliEnvelopeDto(
                EnvelopeSchemaVersion,
                CliValueSanitizer.Value(command),
                result.Success,
                (int)result.ExitCode,
                CliValueSanitizer.Timestamp(timestampUtc),
                result.Data,
                result.Error);
            console.Out.WriteLine(JsonSerializer.Serialize(envelope, CliJson.Options));
        }
        else if (result.Success)
        {
            console.Out.WriteLine(result.Text);
        }
        else
        {
            console.Error.WriteLine(result.Text);
            if (result.Error != null &&
                !string.Equals(
                    CliValueSanitizer.OneLine(result.Text),
                    result.Error.Message,
                    StringComparison.Ordinal))
            {
                console.Error.WriteLine($"Error [{result.Error.Code}]: {result.Error.Message}");
            }
        }

        return (int)result.ExitCode;
    }

    internal static async Task<CliCommandResult> ExecuteInvocationAsync(
        CliInvocation invocation,
        IFeatureCatalog featureCatalog,
        CliDispatcher dispatcher,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(featureCatalog);
        ArgumentNullException.ThrowIfNull(dispatcher);

        var availabilityFailure = CliDispatcher.GetAvailabilityFailure(
            featureCatalog,
            invocation);
        if (availabilityFailure != null)
        {
            return availabilityFailure;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return Canceled();
        }

        try
        {
            var result = await dispatcher.DispatchAsync(invocation, cancellationToken)
                .ConfigureAwait(false);
            return cancellationToken.IsCancellationRequested ? Canceled() : result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Canceled();
        }
        catch
        {
            return InternalFailure();
        }
    }

    internal static CliCommandResult Canceled() =>
        CliCommandResult.Failed(
            CliExitCode.Canceled,
            "Canceled",
            "The command was canceled.");

    private static CliCommandResult InternalFailure() =>
        CliCommandResult.Failed(
            CliExitCode.Failure,
            "InternalFailure",
            "The command failed internally.");
}
