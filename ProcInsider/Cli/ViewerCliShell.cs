using System.Globalization;
using System.Text;
using ProcInsider.Services.Features;

namespace ProcInsider.Cli;

internal sealed record CliShellBuiltInDefinition(
    string Name,
    string Usage,
    string Summary);

internal static class CliShellBuiltInCatalog
{
    public static IReadOnlyList<CliShellBuiltInDefinition> Definitions { get; } =
        Array.AsReadOnly<CliShellBuiltInDefinition>(
        [
            new("help", "help [command...]", "Show shell built-ins and published product commands."),
            new("session show", "session show", "Show the current validated session binding."),
            new(
                "session use",
                "session use \"<absolute-session-root-or-session.json>\"",
                "Validate a replacement session before changing the binding."),
            new("session clear", "session clear", "Clear the shell binding without changing the agent."),
            new("last-exit-code", "last-exit-code", "Show the previous executed command's numeric exit code."),
            new("clear", "clear", "Clear an interactive text terminal."),
            new("exit", "exit", "Exit the shell successfully."),
            new("quit", "quit", "Exit the shell successfully.")
        ]);
}

internal sealed record CliShellHelpDto(
    string Grammar,
    IReadOnlyList<CliHelpCommandDto> BuiltIns,
    IReadOnlyList<CliHelpCommandDto> ProductCommands);

internal sealed record CliShellSessionDto(
    bool Bound,
    string? Session,
    long Generation);

internal sealed record CliShellLastExitCodeDto(int ExitCode);

internal sealed record CliShellActionDto(string Action);

internal sealed class ViewerCliShell : IDisposable
{
    public const string Prompt = "dfiroscope> ";

    private readonly object _sync = new();
    private readonly IFeatureCatalog _featureCatalog;
    private readonly ICliConsole _console;
    private readonly ICliClock _clock;
    private readonly CliDispatcher _dispatcher;
    private readonly ICliInterruptSource _interruptSource;
    private CancellationTokenSource? _lifetimeCancellation;
    private CancellationTokenSource? _activeCommandCancellation;
    private string? _sessionTarget;
    private long _sessionGeneration;
    private int _lastExitCode;
    private bool _disposed;

    public ViewerCliShell(
        IFeatureCatalog featureCatalog,
        ICliConsole console,
        ICliClock clock,
        ICliCommandHandlerFactory handlerFactory,
        ICliInterruptSource interruptSource)
    {
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _console = console ?? throw new ArgumentNullException(nameof(console));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _dispatcher = new CliDispatcher(
            _featureCatalog,
            handlerFactory ?? throw new ArgumentNullException(nameof(handlerFactory)));
        _interruptSource = interruptSource ?? throw new ArgumentNullException(nameof(interruptSource));
    }

    public async Task<int> RunAsync(
        CliInvocation shellInvocation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(shellInvocation);
        if (shellInvocation.Kind != CliCommandKind.Shell)
        {
            throw new ArgumentException("A shell invocation is required.", nameof(shellInvocation));
        }

        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_sync)
        {
            _lifetimeCancellation = lifetime;
        }

        _interruptSource.InterruptRequested += OnInterruptRequested;
        try
        {
            if (!string.IsNullOrWhiteSpace(shellInvocation.SessionTarget))
            {
                var initialGeneration = CurrentGeneration;
                var initialBinding = await ValidateSessionAsync(
                        shellInvocation.SessionTarget,
                        shellInvocation.OutputMode,
                        lifetime.Token)
                    .ConfigureAwait(false);
                if (!IsCurrentGeneration(initialGeneration))
                {
                    initialBinding = Superseded();
                }
                if (!initialBinding.Success)
                {
                    return ViewerCliApplication.Render(
                        "session use",
                        shellInvocation.OutputMode,
                        initialBinding,
                        _console,
                        _clock.UtcNow);
                }

                ReplaceSession(shellInvocation.SessionTarget);
            }

            return await RunLoopAsync(shellInvocation, lifetime).ConfigureAwait(false);
        }
        finally
        {
            _interruptSource.InterruptRequested -= OnInterruptRequested;
            lock (_sync)
            {
                _activeCommandCancellation = null;
                _lifetimeCancellation = null;
            }
        }
    }

    public void Dispose()
    {
        CancellationTokenSource? active;
        CancellationTokenSource? lifetime;
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            active = _activeCommandCancellation;
            lifetime = _lifetimeCancellation;
            _sessionTarget = null;
            Interlocked.Increment(ref _sessionGeneration);
        }

        TryCancel(active);
        TryCancel(lifetime);
    }

    private async Task<int> RunLoopAsync(
        CliInvocation shellInvocation,
        CancellationTokenSource lifetime)
    {
        var showPrompt = shellInvocation.OutputMode == CliOutputMode.Text &&
            !shellInvocation.NoPrompt &&
            !_console.IsInputRedirected &&
            !_console.IsOutputRedirected;
        while (!lifetime.IsCancellationRequested)
        {
            if (showPrompt)
            {
                _console.Out.Write(Prompt);
                _console.Out.Flush();
            }

            string? line;
            try
            {
                line = await _console.In.ReadLineAsync(lifetime.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
            {
                return (int)CliExitCode.Canceled;
            }

            if (line == null)
            {
                return (int)CliExitCode.Success;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using var commandCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                lifetime.Token);
            SetActiveCommand(commandCancellation);
            ShellLineResult execution;
            try
            {
                execution = await ExecuteLineAsync(
                        line,
                        shellInvocation.OutputMode,
                        commandCancellation.Token)
                    .ConfigureAwait(false);
                if (commandCancellation.IsCancellationRequested)
                {
                    execution = new ShellLineResult(
                        execution.Command,
                        ViewerCliApplication.Canceled(),
                        ExitShell: false);
                }
            }
            finally
            {
                ClearActiveCommand(commandCancellation);
            }

            var renderedExit = ViewerCliApplication.Render(
                execution.Command,
                shellInvocation.OutputMode,
                execution.Result,
                _console,
                _clock.UtcNow);
            _lastExitCode = renderedExit;
            if (execution.ExitShell)
            {
                return (int)CliExitCode.Success;
            }
        }

        return (int)CliExitCode.Canceled;
    }

    private async Task<ShellLineResult> ExecuteLineAsync(
        string line,
        CliOutputMode outputMode,
        CancellationToken cancellationToken)
    {
        var tokenized = CliLineTokenizer.Tokenize(line);
        if (!tokenized.Success)
        {
            return Usage("unknown", tokenized.ErrorCode, tokenized.ErrorMessage);
        }

        var tokens = tokenized.Tokens;
        if (tokens.Count == 0)
        {
            return new ShellLineResult(
                "unknown",
                CliCommandResult.Succeeded("No command was executed."),
                ExitShell: false);
        }

        if (EqualsToken(tokens[0], "help"))
        {
            return ExecuteHelp(tokens);
        }

        if (EqualsToken(tokens[0], "session"))
        {
            return await ExecuteSessionBuiltInAsync(tokens, outputMode, cancellationToken)
                .ConfigureAwait(false);
        }

        if (Matches(tokens, "last-exit-code"))
        {
            return new ShellLineResult(
                "last-exit-code",
                CliCommandResult.Succeeded(
                    _lastExitCode.ToString(CultureInfo.InvariantCulture),
                    new CliShellLastExitCodeDto(_lastExitCode)),
                ExitShell: false);
        }

        if (EqualsToken(tokens[0], "last-exit-code"))
        {
            return Usage("last-exit-code", "InvalidShellBuiltIn", "last-exit-code accepts no arguments.");
        }

        if (Matches(tokens, "clear"))
        {
            if (outputMode != CliOutputMode.Text ||
                _console.IsInputRedirected ||
                _console.IsOutputRedirected ||
                !_console.TryClear())
            {
                return new ShellLineResult(
                    "clear",
                    CliCommandResult.Failed(
                        CliExitCode.Rejected,
                        "ClearUnavailable",
                        "clear is available only in an interactive text terminal."),
                    ExitShell: false);
            }

            return new ShellLineResult(
                "clear",
                CliCommandResult.Succeeded("The terminal was cleared.", new CliShellActionDto("clear")),
                ExitShell: false);
        }

        if (EqualsToken(tokens[0], "clear"))
        {
            return Usage("clear", "InvalidShellBuiltIn", "clear accepts no arguments.");
        }

        if (Matches(tokens, "exit") || Matches(tokens, "quit"))
        {
            var command = tokens[0].ToLowerInvariant();
            return new ShellLineResult(
                command,
                CliCommandResult.Succeeded("Shell exited.", new CliShellActionDto(command)),
                ExitShell: true);
        }

        if (EqualsToken(tokens[0], "exit") || EqualsToken(tokens[0], "quit"))
        {
            return Usage(tokens[0], "InvalidShellBuiltIn", $"{tokens[0]} accepts no arguments.");
        }

        var parsed = CliParser.Parse(
            tokens,
            new CliParser.Defaults(outputMode, _sessionTarget, LockOutputMode: true));
        if (!parsed.Success)
        {
            return Usage(
                CliParser.GetAttemptedCommand(tokens),
                parsed.ErrorCode,
                parsed.ErrorMessage);
        }

        var invocation = parsed.Invocation!;
        if (invocation.Kind == CliCommandKind.Shell)
        {
            return Usage(
                "shell",
                "NestedShellNotAllowed",
                "A shell cannot start another shell.");
        }

        var dispatchGeneration = CurrentGeneration;
        var result = await ViewerCliApplication.ExecuteInvocationAsync(
                invocation,
                _featureCatalog,
                _dispatcher,
                cancellationToken)
            .ConfigureAwait(false);
        if (!IsCurrentGeneration(dispatchGeneration))
        {
            result = Superseded();
        }
        return new ShellLineResult(invocation.CommandName, result, ExitShell: false);
    }

    private ShellLineResult ExecuteHelp(IReadOnlyList<string> tokens)
    {
        var published = CliHelpFormatter.GetPublishedDefinitions(_featureCatalog);
        var builtIns = CliShellBuiltInCatalog.Definitions;
        if (tokens.Count == 1)
        {
            return new ShellLineResult(
                "help",
                CliCommandResult.Succeeded(
                    CliShellHelpFormatter.Format(builtIns, published),
                    CliShellHelpFormatter.ToDto(builtIns, published)),
                ExitShell: false);
        }

        var requested = string.Join(' ', tokens.Skip(1));
        var matchingBuiltIns = builtIns
            .Where(definition => string.Equals(
                definition.Name,
                requested,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var matchingProducts = published
            .Where(definition => string.Equals(
                definition.Name,
                requested,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matchingBuiltIns.Length == 0 && matchingProducts.Length == 0)
        {
            return Usage("help", "UnknownHelpTarget", "The requested command is not a published shell command.");
        }

        return new ShellLineResult(
            "help",
            CliCommandResult.Succeeded(
                CliShellHelpFormatter.Format(matchingBuiltIns, matchingProducts),
                CliShellHelpFormatter.ToDto(matchingBuiltIns, matchingProducts)),
            ExitShell: false);
    }

    private async Task<ShellLineResult> ExecuteSessionBuiltInAsync(
        IReadOnlyList<string> tokens,
        CliOutputMode outputMode,
        CancellationToken cancellationToken)
    {
        if (Matches(tokens, "session", "show"))
        {
            var data = CurrentSessionDto();
            return new ShellLineResult(
                "session show",
                CliCommandResult.Succeeded(
                    data.Bound ? $"Session: {data.Session}" : "Session: none",
                    data),
                ExitShell: false);
        }

        if (Matches(tokens, "session", "clear"))
        {
            _sessionTarget = null;
            Interlocked.Increment(ref _sessionGeneration);
            return new ShellLineResult(
                "session clear",
                CliCommandResult.Succeeded(
                    "The shell session binding was cleared.",
                    CurrentSessionDto()),
                ExitShell: false);
        }

        if (tokens.Count == 3 && EqualsToken(tokens[1], "use"))
        {
            var candidate = tokens[2];
            var validationGeneration = CurrentGeneration;
            var validation = await ValidateSessionAsync(candidate, outputMode, cancellationToken)
                .ConfigureAwait(false);
            if (!IsCurrentGeneration(validationGeneration))
            {
                validation = Superseded();
            }
            if (!validation.Success)
            {
                return new ShellLineResult("session use", validation, ExitShell: false);
            }

            ReplaceSession(candidate);
            var data = CurrentSessionDto();
            return new ShellLineResult(
                "session use",
                CliCommandResult.Succeeded($"Session: {data.Session}", data),
                ExitShell: false);
        }

        return Usage(
            "session",
            "InvalidShellBuiltIn",
            "Use session show, session use \"<absolute-session-root-or-session.json>\", or session clear.");
    }

    private Task<CliCommandResult> ValidateSessionAsync(
        string sessionTarget,
        CliOutputMode outputMode,
        CancellationToken cancellationToken) =>
        ViewerCliApplication.ExecuteInvocationAsync(
            new CliInvocation(
                CliCommandKind.AgentStatus,
                CliCommandRegistry.Get(CliCommandKind.AgentStatus).Name,
                outputMode,
                sessionTarget),
            _featureCatalog,
            _dispatcher,
            cancellationToken);

    private void ReplaceSession(string sessionTarget)
    {
        _sessionTarget = sessionTarget;
        Interlocked.Increment(ref _sessionGeneration);
    }

    private long CurrentGeneration => Interlocked.Read(ref _sessionGeneration);

    private bool IsCurrentGeneration(long generation) =>
        generation == CurrentGeneration;

    private CliShellSessionDto CurrentSessionDto() =>
        new(
            !string.IsNullOrWhiteSpace(_sessionTarget),
            string.IsNullOrWhiteSpace(_sessionTarget)
                ? null
                : CliValueSanitizer.Value(_sessionTarget),
            CurrentGeneration);

    private static CliCommandResult Superseded() =>
        CliCommandResult.Failed(
            CliExitCode.Rejected,
            "SessionSuperseded",
            "The shell session binding changed before the command completed.");

    private void OnInterruptRequested(object? sender, EventArgs eventArgs)
    {
        CancellationTokenSource? target;
        lock (_sync)
        {
            target = _activeCommandCancellation;
            if (target == null)
            {
                target = _lifetimeCancellation;
            }
        }

        TryCancel(target);
    }

    private void SetActiveCommand(CancellationTokenSource cancellation)
    {
        lock (_sync)
        {
            _activeCommandCancellation = cancellation;
        }
    }

    private void ClearActiveCommand(CancellationTokenSource cancellation)
    {
        lock (_sync)
        {
            if (ReferenceEquals(_activeCommandCancellation, cancellation))
            {
                _activeCommandCancellation = null;
            }
        }
    }

    private static void TryCancel(CancellationTokenSource? cancellation)
    {
        if (cancellation == null)
        {
            return;
        }

        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static ShellLineResult Usage(
        string command,
        string errorCode,
        string message) =>
        new(
            CliValueSanitizer.Value(command),
            CliCommandResult.Failed(
                CliExitCode.Usage,
                errorCode,
                message),
            ExitShell: false);

    private static bool Matches(IReadOnlyList<string> actual, params string[] expected) =>
        actual.Count == expected.Length &&
        actual.Zip(expected).All(pair => EqualsToken(pair.First, pair.Second));

    private static bool EqualsToken(string? left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private sealed record ShellLineResult(
        string Command,
        CliCommandResult Result,
        bool ExitShell);
}

internal static class CliShellHelpFormatter
{
    public static string Format(
        IReadOnlyList<CliShellBuiltInDefinition> builtIns,
        IReadOnlyList<CliCommandDefinition> productCommands)
    {
        var text = new StringBuilder();
        text.AppendLine("Shell grammar:");
        text.AppendLine("  <command> [options]");
        if (builtIns.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Shell built-ins:");
            foreach (var definition in builtIns)
            {
                text.Append("  ").AppendLine(definition.Usage);
                text.Append("      ").AppendLine(definition.Summary);
            }
        }

        if (productCommands.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Published product commands:");
            foreach (var definition in productCommands.Where(definition => definition.Kind != CliCommandKind.Shell))
            {
                text.Append("  ").AppendLine(ToShellUsage(definition));
                text.Append("      ").AppendLine(definition.Summary);
            }
        }

        return text.ToString().TrimEnd();
    }

    public static CliShellHelpDto ToDto(
        IReadOnlyList<CliShellBuiltInDefinition> builtIns,
        IReadOnlyList<CliCommandDefinition> productCommands) =>
        new(
            "<command> [options]",
            builtIns.Select(definition => new CliHelpCommandDto(
                definition.Name,
                definition.Usage,
                definition.Summary)).ToArray(),
            productCommands
                .Where(definition => definition.Kind != CliCommandKind.Shell)
                .Select(definition => new CliHelpCommandDto(
                    definition.Name,
                    ToShellUsage(definition),
                    definition.Summary))
                .ToArray());

    private static string ToShellUsage(CliCommandDefinition definition)
    {
        const string prefix = "DFIRoscope.Live.exe ";
        return definition.Usage.StartsWith(prefix, StringComparison.Ordinal)
            ? definition.Usage[prefix.Length..]
            : definition.Usage;
    }
}
