using System.Security.Principal;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.Infrastructure;

/// <summary>
/// Machine-scoped atomic storage for validated non-secret Infrastructure configuration.
/// Reading never creates a directory or file. Writes require an administrator authorizer and
/// a successful secret-free audit record; an audit failure restores the prior active bytes.
/// </summary>
public sealed class InfrastructureMachineConfigurationStore
{
    public enum StoreOutcome
    {
        Success = 0,
        Missing = 1,
        Invalid = 2,
        Unauthorized = 3,
        RevisionConflict = 4,
        PromotionFailed = 5,
        AuditFailed = 6,
        RecoveryUnavailable = 7,
        RollbackFailed = 8
    }

    public enum ChangeAction
    {
        Update = 0,
        Rollback = 1
    }

    internal interface IAdministratorAuthorizer
    {
        bool IsAdministrator();
    }

    public interface IChangeAuditSink
    {
        void Record(ConfigurationChangeAuditRecord record);
    }

    public sealed record ConfigurationChangeAuditRecord(
        Contracts.ConfigurationKind Kind,
        ChangeAction Action,
        long PriorRevision,
        long ActiveRevision,
        string CanonicalSha256,
        string AuditCorrelationId,
        DateTime RecordedAtUtc);

    public sealed record ReadResult<T>(
        StoreOutcome Outcome,
        T? Configuration,
        Contracts.ConfigurationSummary? Summary,
        bool RecoveryAvailable,
        IReadOnlyList<Contracts.ValidationDiagnostic> Diagnostics)
        where T : class
    {
        public bool IsSuccess => Outcome == StoreOutcome.Success && Configuration != null;
    }

    public sealed record WriteResult(
        StoreOutcome Outcome,
        Contracts.ConfigurationSummary? Summary,
        string ErrorCode,
        string Message)
    {
        public bool IsSuccess => Outcome == StoreOutcome.Success;
    }

    public sealed record DiagnosticSnapshot(
        StoreOutcome Outcome,
        Contracts.ConfigurationSummary? Summary,
        bool RecoveryAvailable,
        IReadOnlyList<string> ErrorCodes);

    private readonly string _primaryPath;
    private readonly string _recoveryPath;
    private readonly IAdministratorAuthorizer? _authorizer;
    private readonly IChangeAuditSink? _auditSink;
    private readonly Action? _beforePromotion;

    public InfrastructureMachineConfigurationStore(
        string primaryPath,
        string recoveryPath)
        : this(primaryPath, recoveryPath, authorizer: null, auditSink: null, beforePromotion: null)
    {
    }

    internal InfrastructureMachineConfigurationStore(
        string primaryPath,
        string recoveryPath,
        IAdministratorAuthorizer? authorizer,
        IChangeAuditSink? auditSink,
        Action? beforePromotion = null)
    {
        if (string.IsNullOrWhiteSpace(primaryPath))
        {
            throw new ArgumentException("A primary machine-configuration path is required.", nameof(primaryPath));
        }

        if (string.IsNullOrWhiteSpace(recoveryPath))
        {
            throw new ArgumentException("A recovery machine-configuration path is required.", nameof(recoveryPath));
        }

        _primaryPath = Path.GetFullPath(primaryPath);
        _recoveryPath = Path.GetFullPath(recoveryPath);
        if (string.Equals(_primaryPath, _recoveryPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetDirectoryName(_primaryPath),
                Path.GetDirectoryName(_recoveryPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Primary and recovery configuration files must be distinct siblings.", nameof(recoveryPath));
        }

        _authorizer = authorizer;
        _auditSink = auditSink;
        _beforePromotion = beforePromotion;
    }

    public static InfrastructureMachineConfigurationStore ForAgent(
        InfrastructureAgentMachinePaths paths) =>
        new(paths.ConfigurationFilePath, paths.ConfigurationRecoveryFilePath);

    public static InfrastructureMachineConfigurationStore ForServer(
        InfrastructureServerMachinePaths paths) =>
        new(paths.ConfigurationFilePath, paths.ConfigurationRecoveryFilePath);

    internal static InfrastructureMachineConfigurationStore CreateWritableAgentStore(
        InfrastructureAgentMachinePaths paths,
        IChangeAuditSink auditSink) =>
        new(
            paths.ConfigurationFilePath,
            paths.ConfigurationRecoveryFilePath,
            new WindowsAdministratorAuthorizer(),
            auditSink);

    internal static InfrastructureMachineConfigurationStore CreateWritableServerStore(
        InfrastructureServerMachinePaths paths,
        IChangeAuditSink auditSink) =>
        new(
            paths.ConfigurationFilePath,
            paths.ConfigurationRecoveryFilePath,
            new WindowsAdministratorAuthorizer(),
            auditSink);

    public ReadResult<Contracts.InfrastructureAgentConfiguration> ReadAgent() =>
        Read(
            InfrastructureConfigurationCodec.DeserializeAgent,
            InfrastructureConfigurationCodec.Summarize);

    public ReadResult<Contracts.InfrastructureServerConfiguration> ReadServer() =>
        Read(
            InfrastructureConfigurationCodec.DeserializeServer,
            InfrastructureConfigurationCodec.Summarize);

    public DiagnosticSnapshot InspectAgent()
    {
        var result = ReadAgent();
        return Inspect(result);
    }

    public DiagnosticSnapshot InspectServer()
    {
        var result = ReadServer();
        return Inspect(result);
    }

    public WriteResult WriteAgent(
        Contracts.InfrastructureAgentConfiguration configuration,
        long expectedCurrentRevision) =>
        Write(
            configuration,
            expectedCurrentRevision,
            Contracts.ConfigurationKind.Agent,
            InfrastructureConfigurationCodec.SerializeCanonical,
            InfrastructureConfigurationCodec.Summarize,
            ReadAgent);

    public WriteResult WriteServer(
        Contracts.InfrastructureServerConfiguration configuration,
        long expectedCurrentRevision) =>
        Write(
            configuration,
            expectedCurrentRevision,
            Contracts.ConfigurationKind.Server,
            InfrastructureConfigurationCodec.SerializeCanonical,
            InfrastructureConfigurationCodec.Summarize,
            ReadServer);

    public WriteResult RollbackAgent(long expectedCurrentRevision) =>
        Rollback(
            expectedCurrentRevision,
            Contracts.ConfigurationKind.Agent,
            InfrastructureConfigurationCodec.DeserializeAgent,
            InfrastructureConfigurationCodec.Summarize,
            ReadAgent);

    public WriteResult RollbackServer(long expectedCurrentRevision) =>
        Rollback(
            expectedCurrentRevision,
            Contracts.ConfigurationKind.Server,
            InfrastructureConfigurationCodec.DeserializeServer,
            InfrastructureConfigurationCodec.Summarize,
            ReadServer);

    private ReadResult<T> Read<T>(
        Func<ReadOnlySpan<byte>, Contracts.DecodeResult<T>> deserialize,
        Func<T, Contracts.ConfigurationSummary> summarize)
        where T : class
    {
        var recoveryAvailable = TryReadValid(_recoveryPath, deserialize, out _, out _);
        if (!File.Exists(_primaryPath))
        {
            return new ReadResult<T>(
                StoreOutcome.Missing,
                null,
                null,
                recoveryAvailable,
                [Diagnostic("ConfigurationFileMissing", "The active machine configuration is missing.")]);
        }

        if (!TryReadValid(_primaryPath, deserialize, out var configuration, out var diagnostics) || configuration == null)
        {
            return new ReadResult<T>(
                StoreOutcome.Invalid,
                null,
                null,
                recoveryAvailable,
                diagnostics);
        }

        return new ReadResult<T>(
            StoreOutcome.Success,
            configuration,
            summarize(configuration),
            recoveryAvailable,
            Array.Empty<Contracts.ValidationDiagnostic>());
    }

    private WriteResult Write<T>(
        T configuration,
        long expectedCurrentRevision,
        Contracts.ConfigurationKind kind,
        Func<T, byte[]> serialize,
        Func<T, Contracts.ConfigurationSummary> summarize,
        Func<ReadResult<T>> readCurrent)
        where T : class
    {
        if (!IsAuthorized())
        {
            return Failure(StoreOutcome.Unauthorized, "ConfigurationAdministratorRequired", "Machine configuration changes require an Administrator token and an audit sink.");
        }

        byte[] bytes;
        Contracts.ConfigurationSummary proposed;
        try
        {
            bytes = serialize(configuration);
            proposed = summarize(configuration);
        }
        catch (InvalidDataException)
        {
            return Failure(StoreOutcome.Invalid, "ConfigurationValidationFailed", "The proposed machine configuration failed validation.");
        }

        var current = readCurrent();
        if (current.Outcome is not (StoreOutcome.Success or StoreOutcome.Missing))
        {
            return Failure(StoreOutcome.Invalid, "ActiveConfigurationInvalid", "The active configuration is invalid; use an explicit validated recovery operation.");
        }

        var currentRevision = current.Summary?.Revision ?? 0;
        if (currentRevision != expectedCurrentRevision ||
            currentRevision == long.MaxValue ||
            proposed.Revision != currentRevision + 1)
        {
            return Failure(StoreOutcome.RevisionConflict, "ConfigurationRevisionConflict", "The expected/current/proposed configuration revisions are not a consecutive fenced update.");
        }

        string temporaryPath;
        try
        {
            temporaryPath = AllocateTemporaryPath();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure(StoreOutcome.PromotionFailed, "ConfigurationDirectoryUnavailable", "The installed machine configuration directory is unavailable.");
        }

        try
        {
            WriteDurably(temporaryPath, bytes);
            _beforePromotion?.Invoke();
            if (File.Exists(_primaryPath))
            {
                File.Replace(temporaryPath, _primaryPath, _recoveryPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, _primaryPath, overwrite: false);
            }

            try
            {
                _auditSink!.Record(new ConfigurationChangeAuditRecord(
                    kind,
                    ChangeAction.Update,
                    currentRevision,
                    proposed.Revision,
                    proposed.CanonicalSha256,
                    GetAuditCorrelationId(configuration),
                    DateTime.UtcNow));
            }
            catch
            {
                return RestoreAfterFailedAudit(currentRevision == 0, "ConfigurationAuditFailed");
            }

            return new WriteResult(StoreOutcome.Success, proposed, string.Empty, "The validated configuration was atomically promoted and audited.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure(StoreOutcome.PromotionFailed, "ConfigurationPromotionFailed", "The active configuration was not promoted; the prior active file remains authoritative.");
        }
        finally
        {
            DeleteTemporary(temporaryPath);
        }
    }

    private WriteResult Rollback<T>(
        long expectedCurrentRevision,
        Contracts.ConfigurationKind kind,
        Func<ReadOnlySpan<byte>, Contracts.DecodeResult<T>> deserialize,
        Func<T, Contracts.ConfigurationSummary> summarize,
        Func<ReadResult<T>> readCurrent)
        where T : class
    {
        if (!IsAuthorized())
        {
            return Failure(StoreOutcome.Unauthorized, "ConfigurationAdministratorRequired", "Machine configuration rollback requires an Administrator token and an audit sink.");
        }

        var current = readCurrent();
        if (!current.IsSuccess || current.Summary?.Revision != expectedCurrentRevision)
        {
            return Failure(StoreOutcome.RevisionConflict, "ConfigurationRevisionConflict", "The active configuration does not match the expected rollback fence.");
        }

        if (!TryReadValid(_recoveryPath, deserialize, out var recovery, out _) || recovery == null)
        {
            return Failure(StoreOutcome.RecoveryUnavailable, "ConfigurationRecoveryUnavailable", "No valid prior configuration generation is available for rollback.");
        }

        var recoverySummary = summarize(recovery);
        if (recoverySummary.Revision >= expectedCurrentRevision)
        {
            return Failure(StoreOutcome.RecoveryUnavailable, "ConfigurationRecoveryRevisionInvalid", "The recovery generation is not older than the active generation.");
        }

        byte[] recoveryBytes;
        string temporaryPath;
        try
        {
            recoveryBytes = File.ReadAllBytes(_recoveryPath);
            temporaryPath = AllocateTemporaryPath();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure(StoreOutcome.RollbackFailed, "ConfigurationRecoveryReadFailed", "The validated recovery generation could not be prepared for promotion.");
        }

        try
        {
            WriteDurably(temporaryPath, recoveryBytes);
            _beforePromotion?.Invoke();
            File.Replace(temporaryPath, _primaryPath, _recoveryPath, ignoreMetadataErrors: true);
            try
            {
                _auditSink!.Record(new ConfigurationChangeAuditRecord(
                    kind,
                    ChangeAction.Rollback,
                    expectedCurrentRevision,
                    recoverySummary.Revision,
                    recoverySummary.CanonicalSha256,
                    GetAuditCorrelationId(recovery),
                    DateTime.UtcNow));
            }
            catch
            {
                return RestoreAfterFailedAudit(firstWrite: false, "ConfigurationRollbackAuditFailed");
            }

            return new WriteResult(StoreOutcome.Success, recoverySummary, string.Empty, "The validated recovery generation was atomically restored and audited.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure(StoreOutcome.RollbackFailed, "ConfigurationRollbackFailed", "The recovery generation could not be promoted; the prior active file remains authoritative.");
        }
        finally
        {
            DeleteTemporary(temporaryPath);
        }
    }

    private bool TryReadValid<T>(
        string path,
        Func<ReadOnlySpan<byte>, Contracts.DecodeResult<T>> deserialize,
        out T? configuration,
        out IReadOnlyList<Contracts.ValidationDiagnostic> diagnostics)
        where T : class
    {
        configuration = null;
        diagnostics = Array.Empty<Contracts.ValidationDiagnostic>();
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            var info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > Contracts.MaximumDocumentBytes)
            {
                diagnostics = [Diagnostic("ConfigurationFileSizeInvalid", "The machine configuration file has an invalid byte length.")];
                return false;
            }

            var decoded = deserialize(File.ReadAllBytes(path));
            diagnostics = decoded.Diagnostics;
            configuration = decoded.Configuration;
            return decoded.IsValid;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            diagnostics = [Diagnostic("ConfigurationFileReadFailed", "The machine configuration file could not be read.")];
            return false;
        }
    }

    private bool IsAuthorized() =>
        _authorizer?.IsAdministrator() == true && _auditSink != null;

    private string AllocateTemporaryPath()
    {
        var directory = Path.GetDirectoryName(_primaryPath)!;
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("The installed machine configuration directory does not exist.");
        }

        return Path.Combine(directory, $".{Path.GetFileName(_primaryPath)}.tmp-{Guid.NewGuid():N}");
    }

    private static void WriteDurably(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private WriteResult RestoreAfterFailedAudit(bool firstWrite, string errorCode)
    {
        try
        {
            if (firstWrite)
            {
                File.Delete(_primaryPath);
            }
            else
            {
                File.Replace(_recoveryPath, _primaryPath, destinationBackupFileName: null, ignoreMetadataErrors: true);
            }

            return Failure(StoreOutcome.AuditFailed, errorCode, "The audit record failed, so the prior active configuration was restored.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure(StoreOutcome.RollbackFailed, "ConfigurationAuditRollbackFailed", "The audit record and automatic restoration both failed; the service must remain unavailable.");
        }
    }

    private static DiagnosticSnapshot Inspect<T>(ReadResult<T> result)
        where T : class =>
        new(
            result.Outcome,
            result.Summary,
            result.RecoveryAvailable,
            result.Diagnostics.Select(diagnostic => diagnostic.ErrorCode).Distinct(StringComparer.Ordinal).ToArray());

    private static string GetAuditCorrelationId<T>(T configuration) =>
        configuration switch
        {
            Contracts.InfrastructureAgentConfiguration agent => agent.Metadata.AuditCorrelationId,
            Contracts.InfrastructureServerConfiguration server => server.Metadata.AuditCorrelationId,
            _ => string.Empty
        };

    private static void DeleteTemporary(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static Contracts.ValidationDiagnostic Diagnostic(string errorCode, string message) =>
        new(Contracts.DiagnosticSeverity.Error, errorCode, "$", message);

    private static WriteResult Failure(StoreOutcome outcome, string errorCode, string message) =>
        new(outcome, null, errorCode, message);

    private sealed class WindowsAdministratorAuthorizer : IAdministratorAuthorizer
    {
        public bool IsAdministrator()
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            using var identity = WindowsIdentity.GetCurrent();
            if (identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true)
            {
                return false;
            }

            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}

/// <summary>
/// Applies the compiled publication fence before a caller can construct a machine-configuration
/// store. A hidden Infrastructure feature therefore performs no path or file access.
/// </summary>
public static class InfrastructureConfigurationStoreAccess
{
    public static bool TryCreateAgentStore(
        InfrastructureModeAccessService access,
        InfrastructureAgentMachinePaths paths,
        out InfrastructureMachineConfigurationStore? store,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(paths);
        return access.TryCreate(
            ProcInsider.Models.Features.InfrastructureEntryPointKind.ConfigurationAccess,
            () => InfrastructureMachineConfigurationStore.ForAgent(paths),
            out store,
            out decision);
    }

    public static bool TryCreateServerStore(
        InfrastructureModeAccessService access,
        InfrastructureServerMachinePaths paths,
        out InfrastructureMachineConfigurationStore? store,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(paths);
        return access.TryCreate(
            ProcInsider.Models.Features.InfrastructureEntryPointKind.ConfigurationAccess,
            () => InfrastructureMachineConfigurationStore.ForServer(paths),
            out store,
            out decision);
    }

    public static bool TryCreateWritableAgentStore(
        InfrastructureModeAccessService access,
        InfrastructureAgentMachinePaths paths,
        InfrastructureMachineConfigurationStore.IChangeAuditSink auditSink,
        out InfrastructureMachineConfigurationStore? store,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(auditSink);
        return access.TryCreate(
            ProcInsider.Models.Features.InfrastructureEntryPointKind.ConfigurationAccess,
            () => InfrastructureMachineConfigurationStore.CreateWritableAgentStore(paths, auditSink),
            out store,
            out decision);
    }

    public static bool TryCreateWritableServerStore(
        InfrastructureModeAccessService access,
        InfrastructureServerMachinePaths paths,
        InfrastructureMachineConfigurationStore.IChangeAuditSink auditSink,
        out InfrastructureMachineConfigurationStore? store,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(auditSink);
        return access.TryCreate(
            ProcInsider.Models.Features.InfrastructureEntryPointKind.ConfigurationAccess,
            () => InfrastructureMachineConfigurationStore.CreateWritableServerStore(paths, auditSink),
            out store,
            out decision);
    }
}
