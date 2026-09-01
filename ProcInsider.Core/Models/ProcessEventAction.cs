namespace ProcInsider.Models;

/// <summary>
/// Supported normalized event actions.
/// </summary>
public enum ProcessEventAction
{
    ProcessStart,
    ProcessExit,
    Connect,
    Disconnect,
    DnsQuery,
    PowerShellEngineStart,
    PowerShellEngineStop,
    PowerShellCommand,
    PowerShellScriptBlock,
    PowerShellTranscript,
    ImageLoad,
    CreateRemoteThread,
    ProcessAccess,
    RawAccessRead,
    PipeCreated,
    PipeConnected,
    WmiFilter,
    WmiConsumer,
    WmiBinding,
    WmiEvent,
    ProcessTampering,
    RegistryCreateKey,
    RegistrySetValue,
    RegistryDeleteKey,
    RegistryDeleteValue,
    RegistryRenameKey,
    RegistryRenameValue,
    FileCreate,
    FileWrite,
    FileRename,
    FileDelete,
    FileCreateStreamHash,
    GenericSysmon,
    SecurityAudit,
    WindowsEvent,
    EtwEvent
}
