using ProcInsider.Models.Analysis;
using ProcInsider.Services;

namespace ProcInsider.Agent;

/// <summary>
/// Agent-only I/O boundary for one accepted #381 decision. It performs exact
/// evidence resolution, immutable staging, asset re-verification, contained
/// process execution, bounded parsing, and cleanup. It owns no IPC route,
/// persistence, feature publication, annotation, or score policy.
/// </summary>
internal sealed class AgentYaraExecutor
{
    private readonly IYaraEvidenceTargetResolver _resolver;
    private readonly IYaraExecutionWorkspaceContext _workspace;
    private readonly IYaraProcessRunner _processRunner;
    private readonly AgentYaraTargetMaterializer _materializer;
    private readonly IYaraAnalysisResultPersistence _persistence;
    private readonly YaraExecutionAssetPaths _assets;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _singleFlight = new(1, 1);

    public AgentYaraExecutor(
        IYaraEvidenceTargetResolver resolver,
        IYaraExecutionWorkspaceContext workspace,
        IYaraProcessRunner processRunner,
        AgentYaraTargetMaterializer materializer,
        IYaraAnalysisResultPersistence persistence,
        YaraExecutionAssetPaths assets,
        TimeProvider? timeProvider = null)
    {
        _resolver = resolver;
        _workspace = workspace;
        _processRunner = processRunner;
        _materializer = materializer;
        _persistence = persistence;
        _assets = assets;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<YaraAgentExecutionResponse> ExecuteAsync(
        YaraAgentExecutionAuthorizationDecision decision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decision);
        var accepted = ValidateAcceptedDecision(decision);
        if (accepted == null)
        {
            return Reject("The Agent YARA execution decision was not authorized.");
        }

        var request = accepted.Request!;
        var context = accepted.Context!;
        if (!_singleFlight.Wait(0))
        {
            return Unavailable(
                request,
                AnalysisSourceAvailability.Unavailable,
                "Another Agent YARA scan is already running.");
        }

        try
        {
            if (!WorkspaceMatches(context, _workspace.GetCurrent()))
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Stale,
                    "The active workspace changed before YARA target resolution.");
            }

            if (GetUtcNow() >= request.DeadlineUtc)
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Unavailable,
                    "The Agent YARA execution deadline expired before target resolution.");
            }

            var firstResolution = await _resolver.ResolveAsync(request.Target, cancellationToken)
                .ConfigureAwait(false);
            if (firstResolution.State != YaraEvidenceTargetResolutionState.Resolved ||
                firstResolution.Target == null ||
                !ResolvedTargetMatchesRequest(request.Target, firstResolution.Target))
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Unavailable,
                    "The exact YARA evidence target was unavailable or did not match current staging metadata.");
            }

            await using var prepared = await _materializer.PrepareAsync(
                firstResolution.Target,
                request,
                _assets,
                cancellationToken).ConfigureAwait(false);

            var prelaunchResolution = await _resolver.ResolveAsync(request.Target, cancellationToken)
                .ConfigureAwait(false);
            if (!ResolutionMatches(firstResolution, prelaunchResolution) ||
                !WorkspaceMatches(context, _workspace.GetCurrent()))
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Stale,
                    "The YARA evidence scope changed while the target was being staged.");
            }

            await prepared.VerifyAndLockAsync(request, cancellationToken).ConfigureAwait(false);
            var remaining = request.DeadlineUtc - GetUtcNow();
            var authorized = TimeSpan.FromSeconds(request.Limits.WallClockTimeoutSeconds);
            var hostTimeout = remaining < authorized ? remaining : authorized;
            if (hostTimeout <= TimeSpan.Zero)
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Unavailable,
                    "The Agent YARA execution deadline expired before scanner launch.");
            }

            var scannerTimeoutSeconds = Math.Max(
                1,
                Math.Min(
                    request.Limits.WallClockTimeoutSeconds,
                    (int)Math.Floor(hostTimeout.TotalSeconds)) - 1);
            var processRequest = new YaraProcessRunRequest
            {
                ExecutablePath = prepared.ScannerPath,
                WorkingDirectory = prepared.WorkingDirectory,
                Timeout = hostTimeout,
                ProcessMemoryLimitBytes = request.Limits.ProcessMemoryLimitBytes,
                MaximumStdoutBytes = request.Limits.MaximumStdoutBytes,
                MaximumStderrBytes = request.Limits.MaximumStderrBytes,
                Arguments = BuildArguments(
                    prepared,
                    request.Limits,
                    scannerTimeoutSeconds)
            };
            var processResult = await _processRunner.RunAsync(processRequest, cancellationToken)
                .ConfigureAwait(false);
            var completedUtc = GetUtcNow();
            if (processResult.Outcome != YaraProcessRunOutcome.Completed)
            {
                return Unavailable(
                    request,
                    processResult.Outcome == YaraProcessRunOutcome.Canceled
                        ? AnalysisSourceAvailability.Unavailable
                        : AnalysisSourceAvailability.Failed,
                    ProcessDiagnostic(processResult.Outcome),
                    completedUtc);
            }

            if (processResult.ExitCode != 0)
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Failed,
                    "The contained YARA scanner returned a nonzero exit code.",
                    completedUtc);
            }

            var parsed = AgentYaraNdjsonParser.Parse(
                processResult.StandardOutput,
                prepared.TargetPath,
                request,
                completedUtc);
            if (!parsed.Accepted || parsed.Result == null)
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Failed,
                    parsed.Diagnostic,
                    completedUtc);
            }

            var finalResolution = await _resolver.ResolveAsync(request.Target, CancellationToken.None)
                .ConfigureAwait(false);
            if (!ResolutionMatches(firstResolution, finalResolution) ||
                !WorkspaceMatches(context, _workspace.GetCurrent()))
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Stale,
                    "The YARA evidence scope changed before result publication.",
                    completedUtc);
            }

            var finalValidation = YaraAnalysisContractPolicy.Validate(parsed.Result);
            if (!finalValidation.Accepted || finalValidation.Result == null)
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Failed,
                    "The normalized YARA result failed final validation.",
                    completedUtc);
            }

            if (!WorkspaceMatches(context, _workspace.GetCurrent()))
            {
                return Unavailable(
                    request,
                    AnalysisSourceAvailability.Stale,
                    "The YARA workspace changed before normalized result persistence.",
                    completedUtc);
            }

            var persisted = await _persistence.PersistAsync(
                    request,
                    finalValidation.Result,
                    cancellationToken)
                .ConfigureAwait(false);
            return new YaraAgentExecutionResponse
            {
                Outcome = YaraAgentExecutionOutcome.Completed,
                Result = finalValidation.Result,
                Persistence = persisted
            };
        }
        catch (OperationCanceledException)
        {
            return Unavailable(
                request,
                AnalysisSourceAvailability.Unavailable,
                "The Agent YARA scan was canceled.");
        }
        catch (YaraPreparationException ex)
        {
            var availability = ex.Failure is YaraPreparationFailure.TargetHashMismatch or
                YaraPreparationFailure.TargetSizeMismatch
                ? AnalysisSourceAvailability.Stale
                : AnalysisSourceAvailability.Failed;
            return Unavailable(request, availability, PreparationDiagnostic(ex.Failure));
        }
        catch (Exception ex) when (AgentYaraTargetMaterializer.IsFileSystemFailure(ex))
        {
            return Unavailable(
                request,
                AnalysisSourceAvailability.Failed,
                "The Agent could not prepare or clean up the bounded YARA working files.");
        }
        catch (Exception)
        {
            return Unavailable(
                request,
                AnalysisSourceAvailability.Failed,
                "The contained YARA execution or normalized persistence boundary failed.");
        }
        finally
        {
            _singleFlight.Release();
        }
    }

    private static YaraAgentExecutionAuthorizationDecision? ValidateAcceptedDecision(
        YaraAgentExecutionAuthorizationDecision decision)
    {
        if (!decision.Authorized ||
            decision.Failure != YaraAgentExecutionAuthorizationFailure.None ||
            decision.Request == null || decision.Context == null)
        {
            return null;
        }

        var verified = YaraAgentExecutionAuthorizationPolicy.Authorize(
            decision.Request,
            decision.Context);
        return verified.Authorized ? verified : null;
    }

    private static IReadOnlyList<string> BuildArguments(
        YaraPreparedExecution prepared,
        YaraAgentExecutionLimits limits,
        int scannerTimeoutSeconds) =>
    [
        "scan",
        "--output-format=ndjson",
        "--print-namespace",
        "--print-tags",
        "--print-meta",
        "--no-mmap",
        "--threads",
        limits.ScannerThreadCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--cpu-limit",
        limits.CpuLimitPercent.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--timeout",
        scannerTimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--max-matches-per-pattern",
        limits.MaximumStringMatchesPerMatch.ToString(System.Globalization.CultureInfo.InvariantCulture),
        prepared.RulesetPath,
        prepared.TargetPath
    ];

    private static bool WorkspaceMatches(
        YaraAgentExecutionAuthorizationContext authorized,
        YaraExecutionWorkspaceSnapshot current) =>
        current.IsLive && !current.IsSealed && current.IsCurrentAgentOwner &&
        string.Equals(
            authorized.WorkspaceGenerationId,
            current.GenerationId,
            StringComparison.Ordinal);

    private static bool ResolutionMatches(
        YaraEvidenceTargetResolution expected,
        YaraEvidenceTargetResolution actual) =>
        expected.State == YaraEvidenceTargetResolutionState.Resolved &&
        actual.State == YaraEvidenceTargetResolutionState.Resolved &&
        expected.Target != null && expected.Target == actual.Target;

    private static bool ResolvedTargetMatchesRequest(
        YaraScanTarget requested,
        YaraEvidenceTargetRecord resolved) =>
        resolved.Kind == requested.Kind &&
        resolved.EvidenceIdentity == requested.EvidenceIdentity &&
        string.Equals(resolved.SourceRunId, requested.SourceRunId, StringComparison.Ordinal) &&
        resolved.EvidenceReference == requested.EvidenceReference;

    private DateTime GetUtcNow() => _timeProvider.GetUtcNow().UtcDateTime;

    private YaraAgentExecutionResponse Unavailable(
        YaraAgentExecutionRequest request,
        AnalysisSourceAvailability availability,
        string diagnostic,
        DateTime? completedUtc = null)
    {
        var candidate = new YaraScanResult
        {
            ScanId = request.ScanId,
            Availability = availability,
            Target = request.Target,
            Ruleset = request.RulesetIdentity,
            RequestedUtc = request.RequestedUtc,
            CompletedUtc = completedUtc ?? GetUtcNow(),
            Diagnostic = diagnostic,
            Matches = Array.Empty<YaraRuleMatch>()
        };
        var validation = YaraAnalysisContractPolicy.Validate(candidate);
        return validation.Accepted && validation.Result != null
            ? new YaraAgentExecutionResponse
            {
                Outcome = YaraAgentExecutionOutcome.Unavailable,
                Diagnostic = diagnostic,
                Result = validation.Result
            }
            : Reject("The Agent could not construct a valid unavailable YARA result.");
    }

    private static YaraAgentExecutionResponse Reject(string diagnostic) => new()
    {
        Outcome = YaraAgentExecutionOutcome.Rejected,
        Diagnostic = diagnostic
    };

    private static string ProcessDiagnostic(YaraProcessRunOutcome outcome) => outcome switch
    {
        YaraProcessRunOutcome.StartFailed => "The contained YARA scanner could not start.",
        YaraProcessRunOutcome.ContainmentFailed => "The YARA scanner process could not be contained.",
        YaraProcessRunOutcome.TimedOut => "The contained YARA scanner exceeded its wall-clock deadline.",
        YaraProcessRunOutcome.Canceled => "The Agent YARA scan was canceled.",
        YaraProcessRunOutcome.StdoutLimitExceeded => "The YARA scanner exceeded the authorized stdout limit.",
        YaraProcessRunOutcome.StderrLimitExceeded => "The YARA scanner exceeded the authorized stderr limit.",
        _ => "The contained YARA scanner failed."
    };

    private static string PreparationDiagnostic(YaraPreparationFailure failure) => failure switch
    {
        YaraPreparationFailure.UnsafePath =>
            "A composed YARA asset or evidence path failed the containment policy.",
        YaraPreparationFailure.MissingAsset =>
            "A composed YARA asset or evidence file was unavailable.",
        YaraPreparationFailure.ScannerHashMismatch =>
            "The staged YARA scanner hash did not match the admitted scanner identity.",
        YaraPreparationFailure.RulesetHashMismatch =>
            "The staged YARA ruleset hash did not match the admitted ruleset identity.",
        YaraPreparationFailure.ManifestHashMismatch =>
            "The staged YARA manifest hash did not match the admitted manifest identity.",
        YaraPreparationFailure.TargetHashMismatch =>
            "The staged YARA target hash no longer matched the authorized evidence identity.",
        YaraPreparationFailure.TargetSizeMismatch =>
            "The staged YARA target range no longer matched the authorized evidence metadata.",
        _ => "The Agent could not prepare the bounded YARA working set."
    };
}
