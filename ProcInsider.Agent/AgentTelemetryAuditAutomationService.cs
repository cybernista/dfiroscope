using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed record AgentTelemetryAuditAdapterDefinition(
    string SubcategoryGuid,
    string PolicySubcategoryGuid,
    string AdapterId,
    int PrimaryEventId,
    IReadOnlyList<int> ExpectedEventIds,
    AgentTelemetryAuditSaclRequirement SaclRequirement,
    TimeSpan MaximumDuration)
{
    internal bool RequiresSacl => SaclRequirement != AgentTelemetryAuditSaclRequirement.None;
}

internal enum AgentTelemetryAuditSaclRequirement
{
    None,
    Object,
    GlobalFile,
    GlobalRegistry
}

internal static class AgentTelemetryAuditAdapterCatalog
{
    private static readonly IReadOnlyDictionary<string, AgentTelemetryAuditAdapterDefinition> Definitions =
        CreateDefinitions().ToDictionary(item => item.SubcategoryGuid, StringComparer.OrdinalIgnoreCase);

    internal static IReadOnlyList<AgentTelemetryAuditAdapterDefinition> All => Definitions.Values.ToArray();

    internal static bool TryResolve(
        string subcategoryGuid,
        string adapterId,
        out AgentTelemetryAuditAdapterDefinition definition)
    {
        definition = null!;
        return !string.IsNullOrWhiteSpace(subcategoryGuid) &&
               Definitions.TryGetValue(subcategoryGuid, out var candidate) &&
               string.Equals(candidate.AdapterId, adapterId, StringComparison.Ordinal) &&
               (definition = candidate) is not null;
    }

    private static AgentTelemetryAuditAdapterDefinition[] CreateDefinitions() =>
    [
        D("0cce9235-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.LocalUserLifecycle, 4720, 4720, 4722, 4725, 4726, 4738),
        D("0cce9237-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.LocalGroupLifecycle, 4731, 4731, 4734, 4735),
        D("0cce922b-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.ProcessLifecycle, 4688, 4688),
        D("0cce922c-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.ProcessLifecycle, 4689, 4689),
        D("0cce9215-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.LocalLogonLifecycle, 4624, 4624, 4625),
        D("0cce9216-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.LocalLogonLifecycle, 4634, 4634, 4647),
        D("0cce9249-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.LocalLogonLifecycle, 4627, 4627),
        D("0cce921d-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.FileLifecycle, 4663, true, 4656, 4658, 4660, 4663, 4664),
        D("0cce921e-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.RegistryLifecycle, 4657, true, 4656, 4657, 4658, 4660, 4663),
        D("0cce9223-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.FileLifecycle, 4658, true, 4658, 4690),
        D("0cce9234-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.CryptoKeyLifecycle, 5063, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070),
        D("0cce9228-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.PrivilegeUse, 4673, 4673, 4674, 4985),
        D("0cce9229-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.PrivilegeUse, 4673, 4673, 4674, 4985),
        D("0cce9214-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.CryptoKeyLifecycle, 5058, 5058, 5059),
        G("global-object-access-file-system", "0cce921d-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.GlobalFileLifecycle, 4663, AgentTelemetryAuditSaclRequirement.GlobalFile),
        G("global-object-access-registry", "0cce921e-69ae-11d9-bed3-505054503030", AgentTelemetryAuditAdapterIds.GlobalRegistryLifecycle, 4657, AgentTelemetryAuditSaclRequirement.GlobalRegistry),
    ];

    private static AgentTelemetryAuditAdapterDefinition D(
        string guid,
        string adapter,
        int primaryEventId,
        params int[] events) =>
        D(guid, adapter, primaryEventId, AgentTelemetryAuditSaclRequirement.None, events);

    private static AgentTelemetryAuditAdapterDefinition D(
        string guid,
        string adapter,
        int primaryEventId,
        bool requiresSacl,
        params int[] events) => D(
        guid,
        adapter,
        primaryEventId,
        requiresSacl ? AgentTelemetryAuditSaclRequirement.Object : AgentTelemetryAuditSaclRequirement.None,
        events);

    private static AgentTelemetryAuditAdapterDefinition D(
        string guid,
        string adapter,
        int primaryEventId,
        AgentTelemetryAuditSaclRequirement saclRequirement,
        params int[] events) => new(
        Guid.Parse(guid).ToString("D"),
        Guid.Parse(guid).ToString("D"),
        adapter,
        primaryEventId,
        events,
        saclRequirement,
        TimeSpan.FromSeconds(30));

    private static AgentTelemetryAuditAdapterDefinition G(
        string caseId,
        string policyGuid,
        string adapter,
        int primaryEventId,
        AgentTelemetryAuditSaclRequirement saclRequirement) => new(
        caseId,
        Guid.Parse(policyGuid).ToString("D"),
        adapter,
        primaryEventId,
        [primaryEventId],
        saclRequirement,
        TimeSpan.FromSeconds(30));
}

internal sealed record AgentTelemetryAuditRuntimePrerequisites(
    AgentTelemetryAuditPrerequisiteOutcome AuditPolicy,
    AgentTelemetryAuditPrerequisiteOutcome Sacl,
    AgentTelemetryAuditPrerequisiteOutcome Role,
    AgentTelemetryAuditPrerequisiteOutcome SecuritySource,
    string AuditPolicyDetail,
    string SaclDetail,
    string RoleDetail,
    string SecuritySourceDetail,
    string PolicyGeneration);

internal sealed record AgentTelemetryAuditRuntimeExecution(
    AgentTelemetryAuditActivityReceipt Activity,
    AgentTelemetryAuditCleanupReceipt Cleanup);

internal sealed record AgentTelemetryAuditEvidenceCandidate(
    int EventId,
    long? RecordId,
    DateTimeOffset ObservedUtc,
    IReadOnlyDictionary<string, string> MatchedTargetFacts);

internal interface IAgentTelemetryAuditRuntime
{
    string MachineName { get; }

    AgentTelemetryAuditRuntimePrerequisites ReadPrerequisites(AgentTelemetryAuditAdapterDefinition definition);

    Task<AgentTelemetryAuditRuntimeExecution> ExecuteActivityAsync(
        AgentTelemetryAuditAdapterDefinition definition,
        string activityId,
        string correlationId,
        string sourceRunId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<AgentTelemetryAuditEvidenceCandidate>> ReadEvidenceAsync(
        AgentTelemetryAuditAdapterDefinition definition,
        AgentTelemetryAuditActivityReceipt activity,
        CancellationToken cancellationToken);
}

internal sealed class AgentTelemetryAuditAutomationService
{
    private readonly IAgentTelemetryAuditRuntime _runtime;
    private readonly TimeSpan? _maximumDurationOverride;
    private readonly SemaphoreSlim _executionGate = new(1, 1);

    internal AgentTelemetryAuditAutomationService(
        IAgentTelemetryAuditRuntime runtime,
        TimeSpan? maximumDurationOverride = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        if (maximumDurationOverride is { } duration && duration <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(maximumDurationOverride));
        _maximumDurationOverride = maximumDurationOverride;
    }

    internal async Task<AgentTelemetryAuditTestResult> ExecuteAsync(
        RunTelemetryAuditTestCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!AgentTelemetryAuditAdapterCatalog.TryResolve(command.SubcategoryGuid, command.AdapterId, out var definition))
        {
            throw new InvalidOperationException("The requested audit subcategory/adapter pair is not registered.");
        }

        var actualMachine = _runtime.MachineName;
        var exactTarget = command.DisposableTargetConfirmed &&
                          !string.IsNullOrWhiteSpace(command.DesignatedMachineName) &&
                          string.Equals(command.DesignatedMachineName.Trim(), actualMachine, StringComparison.OrdinalIgnoreCase);
        var targetDesignationId = exactTarget
            ? $"ProcInsiderTest_AuditTarget_{actualMachine.ToUpperInvariant()}"
            : string.Empty;
        if (!exactTarget)
        {
            return BaseResult(command, actualMachine, targetDesignationId) with
            {
                ExactTargetDesignated = false,
                Summary = "Rejected before prerequisite reads or activity because the exact local machine was not confirmed as the disposable target."
            };
        }

        await _executionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sourceRunId = "ProcInsiderTest_AuditRun_" + Guid.NewGuid().ToString("N");
            var correlationId = "ProcInsiderTest_AuditCorrelation_" + Guid.NewGuid().ToString("N");
            var activityId = "ProcInsiderTest_AuditActivity_" + Guid.NewGuid().ToString("N");
            var prerequisites = _runtime.ReadPrerequisites(definition);
            var prerequisiteReceipt = ToReceipt(prerequisites);
            if (!PrerequisitesSatisfied(prerequisites))
            {
                return BaseResult(command, actualMachine, targetDesignationId) with
                {
                    ExactTargetDesignated = true,
                    Prerequisites = prerequisiteReceipt,
                    Activity = new AgentTelemetryAuditActivityReceipt
                    {
                        Outcome = AgentTelemetryAuditActivityOutcome.NotRun,
                        AdapterId = definition.AdapterId,
                        ActivityId = activityId,
                        CorrelationId = correlationId,
                        SourceRunId = sourceRunId,
                        Detail = "Activity did not start because an existing prerequisite was not satisfied."
                    },
                    Evidence = new AgentTelemetryAuditEvidenceReceipt
                    {
                        Outcome = AgentTelemetryAuditEvidenceOutcome.NotChecked,
                        CorrelationId = correlationId,
                        SourceRunId = sourceRunId,
                        TargetDesignationId = targetDesignationId,
                        Detail = "Evidence was not queried because activity did not start."
                    },
                    Cleanup = new AgentTelemetryAuditCleanupReceipt
                    {
                        Outcome = AgentTelemetryAuditCleanupOutcome.NotRequired,
                        Detail = "No activity or artifact creation began because a prerequisite was not satisfied."
                    },
                    Summary = "The host was designated, but existing policy, SACL, role, or Security-source prerequisites did not permit activity. Nothing was changed."
                };
            }

            AgentTelemetryAuditRuntimeExecution execution;
            var maximumDuration = _maximumDurationOverride ?? definition.MaximumDuration;
            var effectiveDefinition = definition with { MaximumDuration = maximumDuration };
            var runtimeStartedTimestamp = Stopwatch.GetTimestamp();
            var runtimeDeadlineElapsed = false;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(maximumDuration);
                try
                {
                    execution = await _runtime.ExecuteActivityAsync(
                        effectiveDefinition,
                        activityId,
                        correlationId,
                        sourceRunId,
                        timeout.Token).ConfigureAwait(false);
                    runtimeDeadlineElapsed = timeout.IsCancellationRequested ||
                                             Stopwatch.GetElapsedTime(runtimeStartedTimestamp) > maximumDuration ||
                                             execution.Activity.CompletedUtc - execution.Activity.StartedUtc > maximumDuration;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    execution = TerminalExecution(
                        definition,
                        activityId,
                        correlationId,
                        sourceRunId,
                        AgentTelemetryAuditActivityOutcome.TimedOut,
                        "The fixed activity exceeded its Agent-owned time limit.");
                }
                catch (OperationCanceledException)
                {
                    execution = TerminalExecution(
                        definition,
                        activityId,
                        correlationId,
                        sourceRunId,
                        AgentTelemetryAuditActivityOutcome.Cancelled,
                        "The fixed activity was cancelled.");
                }
            }

            if (execution.Activity.Outcome == AgentTelemetryAuditActivityOutcome.Succeeded &&
                (cancellationToken.IsCancellationRequested || runtimeDeadlineElapsed))
            {
                execution = execution with
                {
                    Activity = execution.Activity with
                    {
                        Outcome = cancellationToken.IsCancellationRequested
                            ? AgentTelemetryAuditActivityOutcome.Cancelled
                            : AgentTelemetryAuditActivityOutcome.TimedOut,
                        Detail = cancellationToken.IsCancellationRequested
                            ? "The fixed activity was cancelled after its non-interruptible local operation completed and cleanup was attempted."
                            : "The fixed activity or cleanup exceeded its Agent-owned time limit; it completed before the non-pass receipt was returned."
                    }
                };
            }

            if (execution.Activity.Outcome == AgentTelemetryAuditActivityOutcome.Cancelled &&
            !cancellationToken.IsCancellationRequested)
            {
                execution = execution with
                {
                    Activity = execution.Activity with
                    {
                        Outcome = AgentTelemetryAuditActivityOutcome.TimedOut,
                        Detail = "The fixed activity exceeded its Agent-owned time limit."
                    }
                };
            }

            var evidence = new AgentTelemetryAuditEvidenceReceipt
            {
                Outcome = AgentTelemetryAuditEvidenceOutcome.NotChecked,
                CorrelationId = correlationId,
                SourceRunId = sourceRunId,
                TargetDesignationId = targetDesignationId,
                Detail = "Evidence was not queried because the fixed activity did not succeed."
            };
            if (execution.Activity.Outcome == AgentTelemetryAuditActivityOutcome.Succeeded)
            {
                try
                {
                    var candidates = await _runtime.ReadEvidenceAsync(definition, execution.Activity, cancellationToken)
                        .ConfigureAwait(false);
                    var selected = candidates
                        .Where(candidate => candidate.EventId == definition.PrimaryEventId &&
                                            candidate.ObservedUtc >= execution.Activity.StartedUtc &&
                                            candidate.ObservedUtc <= execution.Activity.CompletedUtc)
                        .OrderBy(candidate => candidate.ObservedUtc)
                        .ThenBy(candidate => candidate.RecordId ?? long.MaxValue)
                        .FirstOrDefault();
                    evidence = selected is null
                        ? evidence with
                        {
                            Outcome = AgentTelemetryAuditEvidenceOutcome.Missing,
                            Detail = "No exact Security event matched the activity facts inside the bounded correlation window."
                        }
                        : evidence with
                        {
                            Outcome = AgentTelemetryAuditEvidenceOutcome.Observed,
                            EventId = selected.EventId,
                            RecordId = selected.RecordId,
                            ObservedUtc = selected.ObservedUtc,
                            MatchedTargetFacts = selected.MatchedTargetFacts,
                            Detail = $"{candidates.Count} exact Security event(s) matched the unique activity resource facts and bounded correlation window; the earliest matching record is retained."
                        };
                }
                catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException or InvalidOperationException or System.Security.SecurityException)
                {
                    evidence = evidence with
                    {
                        Outcome = AgentTelemetryAuditEvidenceOutcome.Unavailable,
                        Detail = "Security evidence could not be read: " + ex.Message
                    };
                }
            }

            var passed = execution.Activity.Outcome == AgentTelemetryAuditActivityOutcome.Succeeded &&
                     evidence.Outcome == AgentTelemetryAuditEvidenceOutcome.Observed &&
                     execution.Cleanup.Outcome is AgentTelemetryAuditCleanupOutcome.Verified or AgentTelemetryAuditCleanupOutcome.NotRequired;
            return BaseResult(command, actualMachine, targetDesignationId) with
            {
                ExactTargetDesignated = true,
                Prerequisites = prerequisiteReceipt,
                Activity = execution.Activity,
                Evidence = evidence,
                Cleanup = execution.Cleanup,
                Passed = passed,
                Summary = passed
                ? "The fixed activity, exact evidence correlation, existing prerequisites, and declared cleanup all passed."
                : "The test did not pass; prerequisite, activity, evidence, and cleanup receipts remain independent."
            };
        }
        finally
        {
            _executionGate.Release();
        }
    }

    private static AgentTelemetryAuditTestResult BaseResult(
        RunTelemetryAuditTestCommand command,
        string actualMachine,
        string targetDesignationId) => new()
        {
            SubcategoryGuid = command.SubcategoryGuid,
            AdapterId = command.AdapterId,
            DesignatedMachineName = command.DesignatedMachineName,
            ActualMachineName = actualMachine,
            TargetDesignationId = targetDesignationId,
            Activity = new AgentTelemetryAuditActivityReceipt { Outcome = AgentTelemetryAuditActivityOutcome.NotRun },
            Evidence = new AgentTelemetryAuditEvidenceReceipt { Outcome = AgentTelemetryAuditEvidenceOutcome.NotChecked },
            Cleanup = new AgentTelemetryAuditCleanupReceipt { Outcome = AgentTelemetryAuditCleanupOutcome.NotRun }
        };

    private static AgentTelemetryAuditPrerequisiteReceipt ToReceipt(AgentTelemetryAuditRuntimePrerequisites value) => new()
    {
        AuditPolicy = value.AuditPolicy,
        Sacl = value.Sacl,
        Role = value.Role,
        SecuritySource = value.SecuritySource,
        AuditPolicyDetail = value.AuditPolicyDetail,
        SaclDetail = value.SaclDetail,
        RoleDetail = value.RoleDetail,
        SecuritySourceDetail = value.SecuritySourceDetail,
        PolicyGeneration = value.PolicyGeneration
    };

    private static bool PrerequisitesSatisfied(AgentTelemetryAuditRuntimePrerequisites value) =>
        IsSatisfied(value.AuditPolicy) && IsSatisfied(value.Sacl) &&
        IsSatisfied(value.Role) && IsSatisfied(value.SecuritySource);

    private static bool IsSatisfied(AgentTelemetryAuditPrerequisiteOutcome value) =>
        value is AgentTelemetryAuditPrerequisiteOutcome.Satisfied or AgentTelemetryAuditPrerequisiteOutcome.NotRequired;

    private static AgentTelemetryAuditRuntimeExecution TerminalExecution(
        AgentTelemetryAuditAdapterDefinition definition,
        string activityId,
        string correlationId,
        string sourceRunId,
        AgentTelemetryAuditActivityOutcome outcome,
        string detail) => new(
        new AgentTelemetryAuditActivityReceipt
        {
            Outcome = outcome,
            AdapterId = definition.AdapterId,
            ActivityId = activityId,
            CorrelationId = correlationId,
            SourceRunId = sourceRunId,
            StartedUtc = DateTimeOffset.UtcNow,
            CompletedUtc = DateTimeOffset.UtcNow,
            Detail = detail
        },
        new AgentTelemetryAuditCleanupReceipt
        {
            Outcome = AgentTelemetryAuditCleanupOutcome.Failed,
            Detail = "The runtime did not return a cleanup receipt before termination."
        });
}

internal sealed class WindowsAgentTelemetryAuditRuntime : IAgentTelemetryAuditRuntime
{
    private const uint UserPrivilegeUser = 1;
    private const uint UserFlagScript = 1;
    private const uint ServerTypeWorkstation = 0x00000001;
    private const uint ServerTypeDomainController = 0x00000008;
    private const uint ServerTypeDomainBackupController = 0x00000010;
    private readonly Func<CaptureHealthReport> _captureHealth;
    private readonly string _labRoot;
    private readonly AgentTelemetryAuditCleanupRegistry _cleanupRegistry;

    internal WindowsAgentTelemetryAuditRuntime(
        Func<CaptureHealthReport> captureHealth,
        string? labRoot = null)
    {
        _captureHealth = captureHealth ?? throw new ArgumentNullException(nameof(captureHealth));
        _labRoot = Path.GetFullPath(labRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DFIRoscope",
            "TelemetryLab"));
        _cleanupRegistry = new AgentTelemetryAuditCleanupRegistry(_labRoot);
    }

    public string MachineName => Environment.MachineName;

    public AgentTelemetryAuditRuntimePrerequisites ReadPrerequisites(AgentTelemetryAuditAdapterDefinition definition)
    {
        AgentTelemetryAuditPrerequisiteOutcome policyOutcome;
        string policyDetail;
        uint flags = 0;
        try
        {
            var guid = Guid.Parse(definition.PolicySubcategoryGuid);
            var setting = WindowsSystemAuditPolicyReader.Read().SingleOrDefault(item => item.Subcategory == guid);
            flags = setting?.Flags ?? 0;
            policyOutcome = (flags & 0x1) != 0
                ? AgentTelemetryAuditPrerequisiteOutcome.Satisfied
                : AgentTelemetryAuditPrerequisiteOutcome.Missing;
            policyDetail = $"Effective subcategory {guid:B} flags=0x{flags:X}; success auditing is {((flags & 0x1) != 0 ? "enabled" : "disabled")}. Read through the Windows Audit API without auditpol or mutation.";
        }
        catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            policyOutcome = AgentTelemetryAuditPrerequisiteOutcome.Unavailable;
            policyDetail = "Effective audit policy could not be read: " + ex.Message;
        }

        var (saclOutcome, saclDetail) = ReadSaclPrerequisite(definition);
        var (roleOutcome, roleDetail) = ReadMachineRolePrerequisite();
        AgentTelemetryAuditPrerequisiteOutcome sourceOutcome;
        string sourceDetail;
        try
        {
            var health = _captureHealth();
            var security = health.Sources.FirstOrDefault(item =>
                string.Equals(item.Source, "Security", StringComparison.OrdinalIgnoreCase));
            sourceOutcome = security is { IsEnabled: true, IsActive: true } && string.IsNullOrWhiteSpace(security.Error)
                ? AgentTelemetryAuditPrerequisiteOutcome.Satisfied
                : AgentTelemetryAuditPrerequisiteOutcome.Missing;
            sourceDetail = security is null
                ? "The active capture did not report a Security source."
                : $"Security source enabled={security.IsEnabled}; active={security.IsActive}; status={security.Status}; error={security.Error}.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            sourceOutcome = AgentTelemetryAuditPrerequisiteOutcome.Unavailable;
            sourceDetail = "The active Security-source prerequisite could not be read: " + ex.Message;
        }
        var generationMaterial = $"{definition.SubcategoryGuid}|{definition.PolicySubcategoryGuid}|{flags:X}|{saclOutcome}|{saclDetail}|{roleOutcome}|{roleDetail}|{sourceOutcome}|{sourceDetail}";
        var generation = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(generationMaterial)));
        return new AgentTelemetryAuditRuntimePrerequisites(
            policyOutcome,
            saclOutcome,
            roleOutcome,
            sourceOutcome,
            policyDetail,
            saclDetail,
            roleDetail,
            sourceDetail,
            generation);
    }

    public async Task<AgentTelemetryAuditRuntimeExecution> ExecuteActivityAsync(
        AgentTelemetryAuditAdapterDefinition definition,
        string activityId,
        string correlationId,
        string sourceRunId,
        CancellationToken cancellationToken)
    {
        var attemptStarted = DateTimeOffset.UtcNow;
        var cleanupId = "ProcInsiderTest_AuditCleanup_" + Guid.NewGuid().ToString("N");
        var token = correlationId[^Math.Min(20, correlationId.Length)..];
        var artifacts = new List<string>();
        var facts = new Dictionary<string, string>(StringComparer.Ordinal);
        var activityOutcome = AgentTelemetryAuditActivityOutcome.Succeeded;
        var activityDetail = "The registered fixed activity completed.";
        var pendingCleanup = _cleanupRegistry.RetryPending();
        if (!pendingCleanup.Succeeded)
        {
            return new AgentTelemetryAuditRuntimeExecution(
                new AgentTelemetryAuditActivityReceipt
                {
                    Outcome = AgentTelemetryAuditActivityOutcome.NotRun,
                    AdapterId = definition.AdapterId,
                    ActivityId = activityId,
                    CorrelationId = correlationId,
                    SourceRunId = sourceRunId,
                    StartedUtc = attemptStarted,
                    CompletedUtc = DateTimeOffset.UtcNow,
                    Detail = "Activity did not start because an earlier Agent audit artifact still requires cleanup."
                },
                new AgentTelemetryAuditCleanupReceipt
                {
                    Outcome = AgentTelemetryAuditCleanupOutcome.Failed,
                    CleanupId = cleanupId,
                    ArtifactIdentities = pendingCleanup.ArtifactIdentities,
                    Detail = pendingCleanup.Detail
                });
        }

        var started = DateTimeOffset.UtcNow;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (definition.AdapterId)
            {
                case AgentTelemetryAuditAdapterIds.ProcessLifecycle:
                    await RunProcessLifecycleAsync(token, facts, cancellationToken).ConfigureAwait(false);
                    break;
                case AgentTelemetryAuditAdapterIds.FileLifecycle:
                    RunFileLifecycle(definition, cleanupId, token, artifacts, facts);
                    break;
                case AgentTelemetryAuditAdapterIds.RegistryLifecycle:
                    RunRegistryLifecycle(cleanupId, token, artifacts, facts);
                    break;
                case AgentTelemetryAuditAdapterIds.GlobalFileLifecycle:
                    RunFileLifecycle(definition, cleanupId, token, artifacts, facts,
                        "ProcInsiderTest_GlobalObjectAccess_File_");
                    break;
                case AgentTelemetryAuditAdapterIds.GlobalRegistryLifecycle:
                    RunRegistryLifecycle(cleanupId, token, artifacts, facts,
                        "ProcInsiderTest_GlobalObjectAccess_Registry_");
                    break;
                case AgentTelemetryAuditAdapterIds.LocalUserLifecycle:
                    RunLocalUserLifecycle(cleanupId, token, artifacts, facts, createOnly: false);
                    break;
                case AgentTelemetryAuditAdapterIds.LocalGroupLifecycle:
                    RunLocalGroupLifecycle(cleanupId, token, artifacts, facts);
                    break;
                case AgentTelemetryAuditAdapterIds.LocalLogonLifecycle:
                    RunLocalLogonLifecycle(cleanupId, token, artifacts, facts);
                    break;
                case AgentTelemetryAuditAdapterIds.CryptoKeyLifecycle:
                    RunCryptoKeyLifecycle(cleanupId, token, artifacts, facts);
                    break;
                case AgentTelemetryAuditAdapterIds.PrivilegeUse:
                    RunPrivilegeUse(definition, token, facts);
                    break;
                default:
                    throw new InvalidOperationException("The registered audit adapter has no runtime implementation.");
            }
        }
        catch (OperationCanceledException)
        {
            activityOutcome = AgentTelemetryAuditActivityOutcome.Cancelled;
            activityDetail = "The registered fixed activity was cancelled.";
        }
        catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException or IOException or InvalidOperationException or CryptographicException or System.Security.SecurityException)
        {
            activityOutcome = AgentTelemetryAuditActivityOutcome.Failed;
            activityDetail = ex.Message;
        }
        var completed = DateTimeOffset.UtcNow;
        var cleanupResult = artifacts.Count == 0
            ? new AgentTelemetryAuditCleanupBatch(true, Array.Empty<string>(), "The fixed activity created no persistent artifact.")
            : _cleanupRegistry.Cleanup(cleanupId);
        var cleanupOutcome = !cleanupResult.Succeeded
            ? AgentTelemetryAuditCleanupOutcome.Failed
            : artifacts.Count == 0
                ? AgentTelemetryAuditCleanupOutcome.NotRequired
                : AgentTelemetryAuditCleanupOutcome.Verified;
        return new AgentTelemetryAuditRuntimeExecution(
            new AgentTelemetryAuditActivityReceipt
            {
                Outcome = activityOutcome,
                AdapterId = definition.AdapterId,
                ActivityId = activityId,
                CorrelationId = correlationId,
                SourceRunId = sourceRunId,
                StartedUtc = started,
                CompletedUtc = completed,
                TargetFacts = facts,
                Detail = activityDetail
            },
            new AgentTelemetryAuditCleanupReceipt
            {
                Outcome = cleanupOutcome,
                CleanupId = cleanupId,
                ArtifactIdentities = artifacts.Count == 0 ? cleanupResult.ArtifactIdentities : artifacts,
                Detail = cleanupResult.Detail
            });
    }

    public async Task<IReadOnlyList<AgentTelemetryAuditEvidenceCandidate>> ReadEvidenceAsync(
        AgentTelemetryAuditAdapterDefinition definition,
        AgentTelemetryAuditActivityReceipt activity,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        IReadOnlyList<AgentTelemetryAuditEvidenceCandidate> matches = Array.Empty<AgentTelemetryAuditEvidenceCandidate>();
        do
        {
            matches = ReadEvidenceOnce(definition, activity);
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        return matches;
    }

    private (AgentTelemetryAuditPrerequisiteOutcome Outcome, string Detail) ReadSaclPrerequisite(
        AgentTelemetryAuditAdapterDefinition definition)
    {
        if (definition.SaclRequirement == AgentTelemetryAuditSaclRequirement.None)
        {
            return (AgentTelemetryAuditPrerequisiteOutcome.NotRequired,
                "This fixed adapter does not require an object SACL.");
        }

        try
        {
            return new WindowsObjectAuditRuntime().WithPrivilege(() =>
            {
                if (definition.SaclRequirement is AgentTelemetryAuditSaclRequirement.GlobalFile or
                    AgentTelemetryAuditSaclRequirement.GlobalRegistry)
                {
                    return ReadGlobalObjectAccessPrerequisite(definition);
                }

                if (definition.AdapterId == AgentTelemetryAuditAdapterIds.FileLifecycle)
                {
                    if (!Directory.Exists(_labRoot))
                    {
                        return (AgentTelemetryAuditPrerequisiteOutcome.Missing,
                            $"The existing lab root '{_labRoot}' is absent; it was not created or configured.");
                    }

                    var security = new DirectoryInfo(_labRoot).GetAccessControl(AccessControlSections.Audit);
                    var rules = security.GetAuditRules(true, true, typeof(SecurityIdentifier))
                        .OfType<FileSystemAuditRule>();
                    var hasCoverage = HasApplicableFileSuccessAudit(rules, CurrentTokenSids());
                    return (hasCoverage ? AgentTelemetryAuditPrerequisiteOutcome.Satisfied : AgentTelemetryAuditPrerequisiteOutcome.Missing,
                        hasCoverage
                            ? $"The existing lab root '{_labRoot}' has a success-audit rule applicable to the current token, child files, and the generated write access."
                            : $"The existing lab root '{_labRoot}' has no success-audit rule applicable to the current token, child files, and the generated write access; no SACL was added.");
                }

                using var software = Registry.CurrentUser.OpenSubKey("Software", RegistryKeyPermissionCheck.ReadSubTree,
                    System.Security.AccessControl.RegistryRights.ReadPermissions);
                if (software is null)
                {
                    return (AgentTelemetryAuditPrerequisiteOutcome.Unavailable,
                        "HKCU\\Software could not be opened for a read-only SACL inspection.");
                }

                var registrySecurity = software.GetAccessControl(AccessControlSections.Audit);
                var registryRules = registrySecurity.GetAuditRules(true, true, typeof(SecurityIdentifier))
                    .OfType<RegistryAuditRule>();
                var registryHasCoverage = HasApplicableRegistrySuccessAudit(registryRules, CurrentTokenSids());
                return (registryHasCoverage ? AgentTelemetryAuditPrerequisiteOutcome.Satisfied : AgentTelemetryAuditPrerequisiteOutcome.Missing,
                    registryHasCoverage
                        ? "The existing HKCU\\Software root has a success-audit rule applicable to the current token, child keys, and the generated create/set access."
                        : "The existing HKCU\\Software root has no success-audit rule applicable to the current token, child keys, and the generated create/set access; no SACL was added.");
            });
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return (AgentTelemetryAuditPrerequisiteOutcome.Unavailable,
                "The existing SACL could not be read: " + ex.Message);
        }
    }

    private (AgentTelemetryAuditPrerequisiteOutcome Outcome, string Detail) ReadGlobalObjectAccessPrerequisite(
        AgentTelemetryAuditAdapterDefinition definition)
    {
        var tokenSids = CurrentTokenSids();
        if (definition.SaclRequirement == AgentTelemetryAuditSaclRequirement.GlobalFile)
        {
            if (!Directory.Exists(_labRoot))
            {
                return (AgentTelemetryAuditPrerequisiteOutcome.Missing,
                    $"The exact existing test root '{_labRoot}' is absent; it was not created or configured.");
            }

            var global = WindowsGlobalObjectAccessAuditPolicyReader.Read(
                GlobalObjectAccessResourceKind.File,
                tokenSids);
            if (!global.IsAvailable)
            {
                return (AgentTelemetryAuditPrerequisiteOutcome.Unavailable, global.Detail);
            }
            if (!global.HasApplicableSuccessAudit)
            {
                return (AgentTelemetryAuditPrerequisiteOutcome.Missing, global.Detail);
            }

            var security = new DirectoryInfo(_labRoot).GetAccessControl(AccessControlSections.Audit);
            var hasObjectSubstitute = HasApplicableFileSuccessAudit(
                security.GetAuditRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAuditRule>(),
                tokenSids);
            return hasObjectSubstitute
                ? (AgentTelemetryAuditPrerequisiteOutcome.Missing,
                    global.Detail + $" The existing test root '{_labRoot}' also has an applicable per-object success SACL, so evidence could not be attributed exclusively to Global Object Access Auditing; no SACL was changed.")
                : (AgentTelemetryAuditPrerequisiteOutcome.Satisfied,
                    global.Detail + $" The existing test root '{_labRoot}' has no applicable per-object success SACL; no SACL was changed.");
        }

        using var software = Registry.CurrentUser.OpenSubKey(
            "Software",
            RegistryKeyPermissionCheck.ReadSubTree,
            RegistryRights.ReadPermissions);
        if (software is null)
        {
            return (AgentTelemetryAuditPrerequisiteOutcome.Unavailable,
                "HKCU\\Software could not be opened for read-only per-object SACL exclusion.");
        }

        var registryGlobal = WindowsGlobalObjectAccessAuditPolicyReader.Read(
            GlobalObjectAccessResourceKind.Key,
            tokenSids);
        if (!registryGlobal.IsAvailable)
        {
            return (AgentTelemetryAuditPrerequisiteOutcome.Unavailable, registryGlobal.Detail);
        }
        if (!registryGlobal.HasApplicableSuccessAudit)
        {
            return (AgentTelemetryAuditPrerequisiteOutcome.Missing, registryGlobal.Detail);
        }

        var registrySecurity = software.GetAccessControl(AccessControlSections.Audit);
        var registryHasObjectSubstitute = HasApplicableRegistrySetValueSuccessAudit(
            registrySecurity.GetAuditRules(true, true, typeof(SecurityIdentifier)).OfType<RegistryAuditRule>(),
            tokenSids);
        return registryHasObjectSubstitute
            ? (AgentTelemetryAuditPrerequisiteOutcome.Missing,
                registryGlobal.Detail + " The existing HKCU\\Software root also has an applicable per-object success SACL, so evidence could not be attributed exclusively to Global Object Access Auditing; no SACL was changed.")
            : (AgentTelemetryAuditPrerequisiteOutcome.Satisfied,
                registryGlobal.Detail + " The existing HKCU\\Software root has no applicable per-object success SACL; no SACL was changed.");
    }

    internal static bool HasApplicableFileSuccessAudit(
        IEnumerable<FileSystemAuditRule> rules,
        IReadOnlySet<string> tokenSids) =>
        rules.Any(rule =>
            (rule.AuditFlags & AuditFlags.Success) != 0 &&
            WindowsGlobalObjectAccessAuditPolicyReader.IsApplicableTrustee(
                (SecurityIdentifier)rule.IdentityReference,
                tokenSids) &&
            (rule.InheritanceFlags & InheritanceFlags.ObjectInherit) != 0 &&
            (rule.FileSystemRights & FileSystemRights.WriteData) == FileSystemRights.WriteData);

    internal static bool HasApplicableRegistrySuccessAudit(
        IEnumerable<RegistryAuditRule> rules,
        IReadOnlySet<string> tokenSids) =>
        rules.Any(rule =>
            (rule.AuditFlags & AuditFlags.Success) != 0 &&
            WindowsGlobalObjectAccessAuditPolicyReader.IsApplicableTrustee(
                (SecurityIdentifier)rule.IdentityReference,
                tokenSids) &&
            (rule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0 &&
            (rule.RegistryRights & (RegistryRights.CreateSubKey | RegistryRights.SetValue)) ==
            (RegistryRights.CreateSubKey | RegistryRights.SetValue));

    internal static bool HasApplicableRegistrySetValueSuccessAudit(
        IEnumerable<RegistryAuditRule> rules,
        IReadOnlySet<string> tokenSids) =>
        rules.Any(rule =>
            (rule.AuditFlags & AuditFlags.Success) != 0 &&
            WindowsGlobalObjectAccessAuditPolicyReader.IsApplicableTrustee(
                (SecurityIdentifier)rule.IdentityReference,
                tokenSids) &&
            (rule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0 &&
            (rule.RegistryRights & RegistryRights.SetValue) == RegistryRights.SetValue);

    internal static bool IsSupportedLocalMachineRole(uint serverType) =>
        (serverType & ServerTypeWorkstation) != 0 &&
        (serverType & (ServerTypeDomainController | ServerTypeDomainBackupController)) == 0;

    private static IReadOnlySet<string> CurrentTokenSids()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (identity.User is not null) sids.Add(identity.User.Value);
        if (identity.Groups is not null)
        {
            foreach (var group in identity.Groups) sids.Add(group.Value);
        }
        return sids;
    }

    private static (AgentTelemetryAuditPrerequisiteOutcome Outcome, string Detail) ReadMachineRolePrerequisite()
    {
        var result = NetServerGetInfo(null, 101, out var buffer);
        if (result != 0)
        {
            return (AgentTelemetryAuditPrerequisiteOutcome.Unavailable,
                $"The local machine role could not be read (NetServerGetInfo={result}); no activity was permitted.");
        }

        try
        {
            var server = Marshal.PtrToStructure<ServerInfo101>(buffer);
            return IsSupportedLocalMachineRole(server.Type)
                ? (AgentTelemetryAuditPrerequisiteOutcome.Satisfied,
                    $"The read-only local machine type flags 0x{server.Type:X} identify a workstation and not a domain controller; fixed local activity is permitted only on this designated disposable host.")
                : (AgentTelemetryAuditPrerequisiteOutcome.Missing,
                    $"The read-only local machine type flags 0x{server.Type:X} do not identify an eligible workstation or identify a domain controller; fixed local activity is prohibited.");
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
    }

    private static async Task RunProcessLifecycleAsync(
        string token,
        IDictionary<string, string> facts,
        CancellationToken cancellationToken)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var command = Path.Combine(system, "cmd.exe");
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = command,
            Arguments = $"/d /c rem ProcInsiderTest_{token}",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = system
        }) ?? throw new InvalidOperationException("The fixed process marker could not be started.");
        facts["processId"] = process.Id.ToString(CultureInfo.InvariantCulture);
        facts["processIdHex"] = "0x" + process.Id.ToString("x", CultureInfo.InvariantCulture);
        facts["imagePath"] = command;
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"The fixed process marker exited with code {process.ExitCode}.");
        }
    }

    private void RunFileLifecycle(
        AgentTelemetryAuditAdapterDefinition definition,
        string cleanupId,
        string token,
        ICollection<string> artifacts,
        IDictionary<string, string> facts,
        string artifactPrefix = "ProcInsiderTest_Audit_")
    {
        var path = Path.Combine(_labRoot, $"{artifactPrefix}{token}.tmp");
        if (File.Exists(path)) throw new InvalidOperationException("The fixed file target already exists and was not changed.");
        var marker = "ProcInsiderTest_" + token;
        RegisterCleanup(cleanupId, AgentTelemetryAuditArtifactKind.File, path, marker, artifacts);
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            if (definition.PrimaryEventId == 4658)
            {
                facts["handleIdHex"] = FormatPointer(stream.SafeFileHandle.DangerousGetHandle());
                facts["processIdHex"] = "0x" + Environment.ProcessId.ToString("x", CultureInfo.InvariantCulture);
            }
            var bytes = Encoding.UTF8.GetBytes(marker);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        facts["objectName"] = path;
    }

    private void RunRegistryLifecycle(
        string cleanupId,
        string token,
        ICollection<string> artifacts,
        IDictionary<string, string> facts,
        string artifactPrefix = "ProcInsiderTest_Audit_")
    {
        var keyName = $"{artifactPrefix}{token}";
        var identity = "HKCU\\Software\\" + keyName;
        using (var existing = Registry.CurrentUser.OpenSubKey("Software\\" + keyName))
        {
            if (existing is not null)
                throw new InvalidOperationException("The fixed registry target already exists and was not changed.");
        }
        RegisterCleanup(cleanupId, AgentTelemetryAuditArtifactKind.RegistryKey, identity, cleanupId, artifacts);
        using var key = Registry.CurrentUser.CreateSubKey("Software\\" + keyName, writable: true)
            ?? throw new InvalidOperationException("The fixed registry marker could not be created.");
        key.SetValue("ProcInsiderTest_CleanupId", cleanupId, RegistryValueKind.String);
        key.SetValue("ProcInsiderTest_Value", "ProcInsiderTest_" + token, RegistryValueKind.String);
        facts["objectName"] = @"\REGISTRY\USER\" + WindowsIdentity.GetCurrent().User!.Value + "\\Software\\" + keyName;
        facts["objectValueName"] = "ProcInsiderTest_Value";
    }

    private void RunLocalUserLifecycle(
        string cleanupId,
        string token,
        ICollection<string> artifacts,
        IDictionary<string, string> facts,
        bool createOnly)
    {
        var name = BoundedAccountName("ProcInsiderTest_U", token);
        var password = "P!9a" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)) + "z";
        var user = new UserInfo1
        {
            Name = name,
            Password = password,
            Privilege = UserPrivilegeUser,
            Flags = UserFlagScript,
            Comment = cleanupId
        };
        var identity = Environment.MachineName + "\\" + name;
        var existingStatus = NetUserGetInfo(null, name, 0, out var existingBuffer);
        if (existingBuffer != IntPtr.Zero) NetApiBufferFree(existingBuffer);
        if (existingStatus == 0) throw new InvalidOperationException("The fixed local-user target already exists and was not changed.");
        if (existingStatus != 2221) throw new Win32Exception((int)existingStatus, "The fixed local-user target could not be checked before registration.");
        RegisterCleanup(cleanupId, AgentTelemetryAuditArtifactKind.LocalUser, identity, cleanupId, artifacts);
        var result = NetUserAdd(null, 1, ref user, out _);
        if (result != 0) throw new Win32Exception((int)result, "The fixed local test user could not be created.");
        facts["targetUserName"] = name;
        facts["targetDomainName"] = Environment.MachineName;
        if (createOnly)
        {
            facts["password"] = password;
        }
    }

    private void RunLocalGroupLifecycle(
        string cleanupId,
        string token,
        ICollection<string> artifacts,
        IDictionary<string, string> facts)
    {
        var name = BoundedAccountName("ProcInsiderTest_G", token);
        var group = new LocalGroupInfo1 { Name = name, Comment = cleanupId };
        var identity = Environment.MachineName + "\\" + name;
        var existingStatus = NetLocalGroupGetInfo(null, name, 0, out var existingBuffer);
        if (existingBuffer != IntPtr.Zero) NetApiBufferFree(existingBuffer);
        if (existingStatus == 0) throw new InvalidOperationException("The fixed local-group target already exists and was not changed.");
        if (existingStatus != 2220) throw new Win32Exception((int)existingStatus, "The fixed local-group target could not be checked before registration.");
        RegisterCleanup(cleanupId, AgentTelemetryAuditArtifactKind.LocalGroup, identity, cleanupId, artifacts);
        var result = NetLocalGroupAdd(null, 1, ref group, out _);
        if (result != 0) throw new Win32Exception((int)result, "The fixed local test group could not be created.");
        facts["targetUserName"] = name;
        facts["targetDomainName"] = Environment.MachineName;
    }

    private void RunLocalLogonLifecycle(
        string cleanupId,
        string token,
        ICollection<string> artifacts,
        IDictionary<string, string> facts)
    {
        RunLocalUserLifecycle(cleanupId, token, artifacts, facts, createOnly: true);
        var password = facts["password"];
        facts.Remove("password");
        if (!LogonUser(facts["targetUserName"], Environment.MachineName, password, 2, 0, out var logonToken))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The fixed local test logon did not succeed.");
        }
        logonToken.Dispose();
    }

    private void RunCryptoKeyLifecycle(
        string cleanupId,
        string token,
        ICollection<string> artifacts,
        IDictionary<string, string> facts)
    {
        var suffix = new string(token.Where(char.IsAsciiLetterOrDigit).ToArray());
        suffix = suffix[^Math.Min(16, suffix.Length)..];
        var name = "ProcInsiderTest_AuditKey_" + suffix;
        var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
        if (CngKey.Exists(name, provider, CngKeyOpenOptions.UserKey))
            throw new InvalidOperationException("The fixed CNG target already exists and was not changed.");
        RegisterCleanup(cleanupId, AgentTelemetryAuditArtifactKind.CngKey, name, name, artifacts);
        using var key = CngKey.Create(
            CngAlgorithm.Rsa,
            name,
            new CngKeyCreationParameters
            {
                Provider = provider,
                KeyCreationOptions = CngKeyCreationOptions.None,
                KeyUsage = CngKeyUsages.Signing
            });
        facts["objectName"] = name;
    }

    private void RunPrivilegeUse(
        AgentTelemetryAuditAdapterDefinition definition,
        string token,
        IDictionary<string, string> facts)
    {
        facts["processIdHex"] = "0x" + Environment.ProcessId.ToString("x", CultureInfo.InvariantCulture);
        facts["imagePath"] = Environment.ProcessPath
            ?? throw new InvalidOperationException("The fixed privilege-use adapter could not resolve the Agent image path.");

        if (string.Equals(
                definition.SubcategoryGuid,
                "0cce9228-69ae-11d9-bed3-505054503030",
                StringComparison.OrdinalIgnoreCase))
        {
            const string privilege = "SeSecurityPrivilege";
            facts["privilegeName"] = privilege;
            _ = new WindowsObjectAuditRuntime().WithPrivilege(() =>
            {
                var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var security = new DirectoryInfo(systemDirectory).GetAccessControl(AccessControlSections.Audit);
                return security.GetAuditRules(true, true, typeof(SecurityIdentifier)).Count;
            });
            return;
        }

        const string nonSensitivePrivilege = "SeCreateGlobalPrivilege";
        facts["privilegeName"] = nonSensitivePrivilege;
        var mappingName = @"Global\ProcInsiderTest_AuditPrivilege_" + token;
        var mappingHandle = CreateFileMapping(
            new IntPtr(-1),
            IntPtr.Zero,
            0x04,
            0,
            4096,
            mappingName);
        var mappingError = Marshal.GetLastPInvokeError();
        using var mapping = new SafeFileHandle(mappingHandle, ownsHandle: true);
        if (mapping.IsInvalid)
        {
            throw new Win32Exception(mappingError,
                "The fixed global file-mapping privilege activity could not be created.");
        }
        if (mappingError == 183)
        {
            throw new InvalidOperationException("The fixed global file-mapping target already existed and was not used.");
        }
    }

    private void RegisterCleanup(
        string cleanupId,
        AgentTelemetryAuditArtifactKind kind,
        string identity,
        string ownershipMarker,
        ICollection<string> artifacts)
    {
        var registration = new AgentTelemetryAuditCleanupRegistration(
            cleanupId,
            kind,
            identity,
            ownershipMarker,
            DateTimeOffset.UtcNow);
        if (!_cleanupRegistry.TryRegister(registration, out var error))
            throw new IOException("The exact artifact cleanup registration could not be durably written before creation: " + error);
        artifacts.Add(identity);
    }

    private static string BoundedAccountName(string prefix, string token)
    {
        var suffix = new string(token.Where(char.IsAsciiLetterOrDigit).ToArray());
        suffix = suffix[^Math.Min(8, suffix.Length)..];
        return (prefix + suffix)[..Math.Min(20, prefix.Length + suffix.Length)];
    }

    private static string FormatPointer(IntPtr value) =>
        "0x" + unchecked((ulong)value.ToInt64()).ToString("x", CultureInfo.InvariantCulture);

    private static IReadOnlyList<AgentTelemetryAuditEvidenceCandidate> ReadEvidenceOnce(
        AgentTelemetryAuditAdapterDefinition definition,
        AgentTelemetryAuditActivityReceipt activity)
    {
        var start = activity.StartedUtc;
        var end = activity.CompletedUtc;
        var eventClause = string.Join(" or ", definition.ExpectedEventIds.Select(id => $"EventID={id}"));
        var query = new EventLogQuery(
            "Security",
            PathType.LogName,
            $"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and ({eventClause})]]")
        {
            ReverseDirection = true,
            TolerateQueryErrors = false
        };
        using var reader = new EventLogReader(query);
        var candidates = new List<AgentTelemetryAuditEvidenceCandidate>();
        for (var count = 0; count < 256; count++)
        {
            using var record = reader.ReadEvent();
            if (record is null) break;
            var observed = record.TimeCreated.HasValue
                ? new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime())
                : DateTimeOffset.MinValue;
            if (observed > end) continue;
            if (observed < start) break;
            if (record.Id != definition.PrimaryEventId) continue;
            if (!TryMatchEventFacts(definition, activity.TargetFacts, record.ToXml(), out var matched))
            {
                continue;
            }
            candidates.Add(new AgentTelemetryAuditEvidenceCandidate(record.Id, record.RecordId, observed, matched));
        }

        return candidates;
    }

    internal static bool TryMatchEventFacts(
        AgentTelemetryAuditAdapterDefinition definition,
        IReadOnlyDictionary<string, string> targetFacts,
        string eventXml,
        out IReadOnlyDictionary<string, string> matchedFacts)
    {
        matchedFacts = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            var fields = XDocument.Parse(eventXml)
                .Descendants()
                .Where(element => element.Name.LocalName == "Data")
                .Where(element => element.Attribute("Name") is not null)
                .GroupBy(
                    element => element.Attribute("Name")!.Value,
                    element => element.Value,
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => (IReadOnlyList<string>)group.ToArray(),
                    StringComparer.OrdinalIgnoreCase);
            var requiredFacts = RequiredFacts(definition);
            var matched = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var required in requiredFacts)
            {
                if (!targetFacts.TryGetValue(required, out var expected) ||
                    string.IsNullOrWhiteSpace(expected) ||
                    !MatchesEventField(definition, fields, required, expected))
                {
                    return false;
                }
                matched[required] = expected;
            }
            matchedFacts = matched;
            return requiredFacts.Count > 0;
        }
        catch (System.Xml.XmlException)
        {
            return false;
        }
    }

    private static IReadOnlyList<string> RequiredFacts(AgentTelemetryAuditAdapterDefinition definition) =>
        definition.AdapterId switch
        {
            AgentTelemetryAuditAdapterIds.ProcessLifecycle => ["processIdHex", "imagePath"],
            AgentTelemetryAuditAdapterIds.LocalUserLifecycle or
            AgentTelemetryAuditAdapterIds.LocalGroupLifecycle or
            AgentTelemetryAuditAdapterIds.LocalLogonLifecycle => ["targetUserName", "targetDomainName"],
            AgentTelemetryAuditAdapterIds.FileLifecycle when definition.PrimaryEventId == 4658 =>
                ["handleIdHex", "processIdHex"],
            AgentTelemetryAuditAdapterIds.FileLifecycle or
            AgentTelemetryAuditAdapterIds.GlobalFileLifecycle => ["objectName"],
            AgentTelemetryAuditAdapterIds.RegistryLifecycle or
            AgentTelemetryAuditAdapterIds.GlobalRegistryLifecycle => ["objectName", "objectValueName"],
            AgentTelemetryAuditAdapterIds.CryptoKeyLifecycle => ["objectName"],
            AgentTelemetryAuditAdapterIds.PrivilegeUse => ["processIdHex", "imagePath", "privilegeName"],
            _ => []
        };

    private static bool MatchesEventField(
        AgentTelemetryAuditAdapterDefinition definition,
        IReadOnlyDictionary<string, IReadOnlyList<string>> fields,
        string fact,
        string expected)
    {
        var names = fact switch
        {
            "processIdHex" when definition.PrimaryEventId == 4688 => new[] { "NewProcessId" },
            "processIdHex" => ["ProcessId"],
            "imagePath" when definition.PrimaryEventId == 4688 => ["NewProcessName"],
            "imagePath" => ["ProcessName"],
            "targetUserName" => ["TargetUserName", "SubjectUserName"],
            "targetDomainName" => ["TargetDomainName", "SubjectDomainName"],
            "objectName" when definition.AdapterId == AgentTelemetryAuditAdapterIds.CryptoKeyLifecycle => ["KeyName"],
            "objectName" => ["ObjectName"],
            "objectValueName" => ["ObjectValueName"],
            "handleIdHex" => ["HandleId"],
            "privilegeName" => ["PrivilegeList"],
            _ => Array.Empty<string>()
        };
        foreach (var name in names)
        {
            if (!fields.TryGetValue(name, out var values)) continue;
            if (fact == "privilegeName")
            {
                if (values.Any(value => value
                        .Split([' ', '\t', '\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries)
                        .Contains(expected, StringComparer.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            else if (values.Any(value => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }
        return false;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string Password;
        public uint PasswordAge;
        public uint Privilege;
        [MarshalAs(UnmanagedType.LPWStr)] public string? HomeDirectory;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string? ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LocalGroupInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServerInfo101
    {
        public uint PlatformId;
        public IntPtr Name;
        public uint VersionMajor;
        public uint VersionMinor;
        public uint Type;
        public IntPtr Comment;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserAdd(string? serverName, uint level, ref UserInfo1 buffer, out uint parameterError);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserDel(string? serverName, string userName);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserGetInfo(string? serverName, string userName, uint level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupAdd(string? serverName, uint level, ref LocalGroupInfo1 buffer, out uint parameterError);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupDel(string? serverName, string groupName);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupGetInfo(string? serverName, string groupName, uint level, out IntPtr buffer);

    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetServerGetInfo(string? serverName, uint level, out IntPtr buffer);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(
        string userName,
        string? domain,
        string password,
        int logonType,
        int logonProvider,
        out SafeAccessTokenHandle token);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileMapping(
        IntPtr file,
        IntPtr securityAttributes,
        uint protection,
        uint maximumSizeHigh,
        uint maximumSizeLow,
        string name);
}
