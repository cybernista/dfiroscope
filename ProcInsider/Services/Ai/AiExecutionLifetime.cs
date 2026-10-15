using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

/// <summary>
/// Holds a process-lifetime Windows object so a persisted AI execution can be
/// classified after the process exits without relying on a recyclable PID.
/// </summary>
public sealed class AiExecutionLifetime : IDisposable
{
    private const string MutexPrefix = @"Local\DFIRoscope.AiExecution.";
    private const string MachineGuidKey = @"SOFTWARE\Microsoft\Cryptography";
    private const uint SynchronizeAccess = 0x00100000;
    private const int ErrorFileNotFound = 2;
    private Mutex? _mutex;

    private AiExecutionLifetime(Mutex mutex, AiExecutionOwner owner)
    {
        _mutex = mutex;
        Owner = owner;
    }

    public AiExecutionOwner Owner { get; }

    public bool IsDisposed => Volatile.Read(ref _mutex) is null;

    public static AiExecutionLifetime Create()
    {
        if (!TryGetMachineFingerprint(out var fingerprint))
        {
            throw new InvalidOperationException(
                "The Windows machine identity is unavailable; an AI execution lifetime cannot be established.");
        }

        using var currentProcess = Process.GetCurrentProcess();
        var sessionId = currentProcess.SessionId;
        if (sessionId < 0)
        {
            throw new InvalidOperationException(
                "The Windows session identity is unavailable; an AI execution lifetime cannot be established.");
        }

        while (true)
        {
            var lifetimeId = Guid.NewGuid().ToString("N");
            var mutex = new Mutex(initiallyOwned: false, MutexPrefix + lifetimeId, out var createdNew);
            if (createdNew)
            {
                return new AiExecutionLifetime(
                    mutex,
                    new AiExecutionOwner(lifetimeId, fingerprint, sessionId));
            }

            // Even a UUID collision must never reuse another execution's lifetime.
            mutex.Dispose();
        }
    }

    public static AiExecutionOwnerState GetOwnerState(AiExecutionOwner? owner)
    {
        if (owner is null ||
            !Guid.TryParseExact(owner.LifetimeId, "N", out var lifetimeId) ||
            lifetimeId == Guid.Empty ||
            !string.Equals(owner.LifetimeId, lifetimeId.ToString("N"), StringComparison.Ordinal) ||
            !IsCanonicalFingerprint(owner.MachineFingerprint) ||
            owner.WindowsSessionId < 0 ||
            !TryGetMachineFingerprint(out var currentFingerprint) ||
            !string.Equals(owner.MachineFingerprint, currentFingerprint, StringComparison.Ordinal))
        {
            return AiExecutionOwnerState.Unknown;
        }

        try
        {
            using var currentProcess = Process.GetCurrentProcess();
            if (currentProcess.SessionId != owner.WindowsSessionId)
                return AiExecutionOwnerState.Unknown;

            using var mutex = OpenMutex(SynchronizeAccess, false, MutexPrefix + owner.LifetimeId);
            if (!mutex.IsInvalid)
            {
                return AiExecutionOwnerState.Active;
            }

            // Mutex.TryOpenExisting also returns false for a different object type
            // at this name. Only ERROR_FILE_NOT_FOUND proves absence.
            return Marshal.GetLastPInvokeError() == ErrorFileNotFound
                ? AiExecutionOwnerState.Abandoned
                : AiExecutionOwnerState.Unknown;
        }
        catch (Exception)
        {
            // Access denial, object type collisions, and probe failures cannot
            // establish that the original lifetime has ended.
            return AiExecutionOwnerState.Unknown;
        }
    }

    public void Dispose() => Interlocked.Exchange(ref _mutex, null)?.Dispose();

    private static bool IsCanonicalFingerprint(string? fingerprint)
    {
        if (fingerprint is null || fingerprint.Length != 64)
            return false;

        foreach (var character in fingerprint)
        {
            if (character is not (>= '0' and <= '9' or >= 'A' and <= 'F'))
                return false;
        }

        return true;
    }

    private static bool TryGetMachineFingerprint(out string fingerprint)
    {
        fingerprint = string.Empty;
        try
        {
            using var machineHive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var cryptographyKey = machineHive.OpenSubKey(MachineGuidKey, writable: false);
            if (cryptographyKey?.GetValue("MachineGuid") is not string value ||
                !Guid.TryParse(value, out var machineGuid) ||
                machineGuid == Guid.Empty)
            {
                return false;
            }

            var canonicalGuid = machineGuid.ToString("D");
            fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalGuid)));
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "OpenMutexW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle OpenMutex(uint desiredAccess, bool inheritHandle, string name);
}
