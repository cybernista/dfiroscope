using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace ProcInsider.Agent;

internal enum AgentTelemetryAuditArtifactKind
{
    File,
    RegistryKey,
    LocalUser,
    LocalGroup,
    CngKey
}

internal sealed record AgentTelemetryAuditCleanupRegistration(
    string CleanupId,
    AgentTelemetryAuditArtifactKind Kind,
    string Target,
    string OwnershipMarker,
    DateTimeOffset RegisteredUtc);

internal sealed record AgentTelemetryAuditCleanupBatch(
    bool Succeeded,
    IReadOnlyList<string> ArtifactIdentities,
    string Detail);

/// <summary>
/// Agent-owned durable cleanup journal for issue #640 fixed audit artifacts. Entries are
/// written through before creation, removed only after exact absence is verified, and
/// retained after every failed or unsafe retry.
/// </summary>
internal sealed class AgentTelemetryAuditCleanupRegistry
{
    internal const string FileName = "ProcInsiderTest_AgentAuditCleanupRegistry.jsonl";
    private const string Prefix = "ProcInsiderTest_";
    private const string RegistryMarkerName = "ProcInsiderTest_CleanupId";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private readonly string _labRoot;

    internal AgentTelemetryAuditCleanupRegistry(string labRoot)
    {
        _labRoot = Path.GetFullPath(labRoot ?? throw new ArgumentNullException(nameof(labRoot)));
        RegistryPath = Path.Combine(_labRoot, FileName);
    }

    internal string RegistryPath { get; }

    internal bool TryRegister(
        AgentTelemetryAuditCleanupRegistration registration,
        out string error)
    {
        error = string.Empty;
        if (!IsSafe(registration, out var safetyError))
        {
            error = safetyError ?? "The cleanup registration failed its safety validation.";
            return false;
        }

        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(_labRoot);
                using var stream = new FileStream(
                    RegistryPath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.Read,
                    4096,
                    FileOptions.WriteThrough);
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(registration, JsonOptions) + Environment.NewLine);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    internal AgentTelemetryAuditCleanupBatch RetryPending() => Cleanup(registration => true);

    internal AgentTelemetryAuditCleanupBatch Cleanup(string cleanupId) =>
        Cleanup(registration => string.Equals(registration.CleanupId, cleanupId, StringComparison.Ordinal));

    internal IReadOnlyList<AgentTelemetryAuditCleanupRegistration> ReadPending(out IReadOnlyList<string> errors)
    {
        lock (_gate)
        {
            return ReadPendingCore(out errors);
        }
    }

    private AgentTelemetryAuditCleanupBatch Cleanup(Func<AgentTelemetryAuditCleanupRegistration, bool> select)
    {
        lock (_gate)
        {
            var registrations = ReadPendingCore(out var readErrors);
            if (readErrors.Count > 0)
            {
                return new AgentTelemetryAuditCleanupBatch(
                    false,
                    registrations.Where(select).Select(item => item.Target).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                    "The durable Agent audit cleanup journal could not be read cleanly: " + string.Join("; ", readErrors));
            }

            var selected = registrations.Where(select).ToArray();
            if (selected.Length == 0)
            {
                return new AgentTelemetryAuditCleanupBatch(true, Array.Empty<string>(), "No durable Agent audit cleanup entry required retry.");
            }

            var remaining = registrations.Where(item => !select(item)).ToList();
            var failures = new List<string>();
            foreach (var registration in selected)
            {
                try
                {
                    CleanupOne(registration);
                }
                catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or
                                           InvalidOperationException or CryptographicException or System.Security.SecurityException)
                {
                    remaining.Add(registration);
                    failures.Add($"{registration.Target}: {ex.Message}");
                }
            }

            if (!TryRewrite(remaining, out var rewriteError))
            {
                failures.Add("cleanup journal update: " + rewriteError);
            }

            var targets = selected.Select(item => item.Target).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            return failures.Count == 0
                ? new AgentTelemetryAuditCleanupBatch(
                    true,
                    targets,
                    "Every selected durable cleanup entry was removed or already absent, verified, and retired from the Agent journal.")
                : new AgentTelemetryAuditCleanupBatch(
                    false,
                    targets,
                    "Cleanup remains registered for retry: " + string.Join("; ", failures));
        }
    }

    private IReadOnlyList<AgentTelemetryAuditCleanupRegistration> ReadPendingCore(out IReadOnlyList<string> errors)
    {
        var registrations = new List<AgentTelemetryAuditCleanupRegistration>();
        var failures = new List<string>();
        if (!File.Exists(RegistryPath))
        {
            errors = failures;
            return registrations;
        }

        try
        {
            var lineNumber = 0;
            foreach (var line in File.ReadLines(RegistryPath))
            {
                lineNumber++;
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var registration = JsonSerializer.Deserialize<AgentTelemetryAuditCleanupRegistration>(line, JsonOptions);
                    if (registration is null)
                    {
                        failures.Add($"line {lineNumber}: empty registration");
                    }
                    else if (!IsSafe(registration, out var safetyError))
                    {
                        failures.Add($"line {lineNumber}: {safetyError ?? "unsafe registration"}");
                    }
                    else
                    {
                        registrations.Add(registration);
                    }
                }
                catch (JsonException ex)
                {
                    failures.Add($"line {lineNumber}: {ex.Message}");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            failures.Add(ex.Message);
        }

        errors = failures;
        return registrations;
    }

    private bool TryRewrite(IReadOnlyList<AgentTelemetryAuditCleanupRegistration> registrations, out string error)
    {
        error = string.Empty;
        var temporary = Path.Combine(_labRoot, $"ProcInsiderTest_AgentAuditCleanupRegistry_{Guid.NewGuid():N}.tmp");
        try
        {
            if (registrations.Count == 0)
            {
                if (File.Exists(RegistryPath)) File.Delete(RegistryPath);
                return true;
            }

            Directory.CreateDirectory(_labRoot);
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                foreach (var registration in registrations)
                {
                    var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(registration, JsonOptions) + Environment.NewLine);
                    stream.Write(bytes);
                }
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, RegistryPath, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            try
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
            catch
            {
            }
        }
    }

    private void CleanupOne(AgentTelemetryAuditCleanupRegistration registration)
    {
        if (!IsSafe(registration, out var safetyError))
        {
            throw new InvalidOperationException(safetyError);
        }

        switch (registration.Kind)
        {
            case AgentTelemetryAuditArtifactKind.File:
                CleanupFile(registration);
                break;
            case AgentTelemetryAuditArtifactKind.RegistryKey:
                CleanupRegistryKey(registration);
                break;
            case AgentTelemetryAuditArtifactKind.LocalUser:
                CleanupLocalUser(registration);
                break;
            case AgentTelemetryAuditArtifactKind.LocalGroup:
                CleanupLocalGroup(registration);
                break;
            case AgentTelemetryAuditArtifactKind.CngKey:
                CleanupCngKey(registration);
                break;
            default:
                throw new InvalidOperationException("The durable cleanup entry has an unsupported artifact kind.");
        }
    }

    private static void CleanupFile(AgentTelemetryAuditCleanupRegistration registration)
    {
        if (!File.Exists(registration.Target)) return;
        var marker = File.ReadAllText(registration.Target);
        if (!string.Equals(marker, registration.OwnershipMarker, StringComparison.Ordinal))
            throw new InvalidOperationException("The file ownership marker changed; deletion was withheld.");
        File.Delete(registration.Target);
        if (File.Exists(registration.Target)) throw new IOException("The file remains after cleanup.");
    }

    private static void CleanupRegistryKey(AgentTelemetryAuditCleanupRegistration registration)
    {
        const string prefix = "HKCU\\Software\\";
        var subKey = registration.Target[prefix.Length..];
        using (var key = Registry.CurrentUser.OpenSubKey("Software\\" + subKey))
        {
            if (key is null) return;
            if (!string.Equals(key.GetValue(RegistryMarkerName) as string, registration.OwnershipMarker, StringComparison.Ordinal))
                throw new InvalidOperationException("The registry ownership marker changed; deletion was withheld.");
        }
        Registry.CurrentUser.DeleteSubKeyTree("Software\\" + subKey, throwOnMissingSubKey: false);
        using var remaining = Registry.CurrentUser.OpenSubKey("Software\\" + subKey);
        if (remaining is not null) throw new IOException("The registry key remains after cleanup.");
    }

    private static void CleanupLocalUser(AgentTelemetryAuditCleanupRegistration registration)
    {
        var name = registration.Target[(registration.Target.IndexOf('\\') + 1)..];
        var status = NetUserGetInfo(null, name, 1, out var buffer);
        if (status == 2221) return;
        if (status != 0) throw new Win32Exception((int)status, "The fixed local test user could not be inspected for cleanup.");
        try
        {
            var info = Marshal.PtrToStructure<UserInfo1>(buffer);
            if (!string.Equals(info.Comment, registration.OwnershipMarker, StringComparison.Ordinal))
                throw new InvalidOperationException("The local-user ownership marker changed; deletion was withheld.");
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
        status = NetUserDel(null, name);
        if (status is not 0 and not 2221) throw new Win32Exception((int)status, "The fixed local test user could not be removed.");
        status = NetUserGetInfo(null, name, 0, out buffer);
        if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        if (status == 0) throw new IOException("The fixed local test user remains after cleanup.");
        if (status != 2221) throw new Win32Exception((int)status, "The fixed local test user cleanup could not be verified.");
    }

    private static void CleanupLocalGroup(AgentTelemetryAuditCleanupRegistration registration)
    {
        var name = registration.Target[(registration.Target.IndexOf('\\') + 1)..];
        var status = NetLocalGroupGetInfo(null, name, 1, out var buffer);
        if (status == 2220) return;
        if (status != 0) throw new Win32Exception((int)status, "The fixed local test group could not be inspected for cleanup.");
        try
        {
            var info = Marshal.PtrToStructure<LocalGroupInfo1>(buffer);
            if (!string.Equals(info.Comment, registration.OwnershipMarker, StringComparison.Ordinal))
                throw new InvalidOperationException("The local-group ownership marker changed; deletion was withheld.");
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
        status = NetLocalGroupDel(null, name);
        if (status is not 0 and not 2220) throw new Win32Exception((int)status, "The fixed local test group could not be removed.");
        status = NetLocalGroupGetInfo(null, name, 0, out buffer);
        if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        if (status == 0) throw new IOException("The fixed local test group remains after cleanup.");
        if (status != 2220) throw new Win32Exception((int)status, "The fixed local test group cleanup could not be verified.");
    }

    private static void CleanupCngKey(AgentTelemetryAuditCleanupRegistration registration)
    {
        if (!string.Equals(registration.Target, registration.OwnershipMarker, StringComparison.Ordinal))
            throw new InvalidOperationException("The CNG cleanup entry has no exact ownership marker.");
        var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
        if (!CngKey.Exists(registration.Target, provider, CngKeyOpenOptions.UserKey)) return;
        using (var key = CngKey.Open(registration.Target, provider, CngKeyOpenOptions.UserKey)) key.Delete();
        if (CngKey.Exists(registration.Target, provider, CngKeyOpenOptions.UserKey))
            throw new IOException("The fixed current-user cryptographic key remains after cleanup.");
    }

    private bool IsSafe(AgentTelemetryAuditCleanupRegistration registration, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(registration.CleanupId) ||
            !registration.CleanupId.StartsWith("ProcInsiderTest_AuditCleanup_", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(registration.Target) ||
            string.IsNullOrWhiteSpace(registration.OwnershipMarker))
        {
            error = "The cleanup identity, target, or ownership marker is invalid.";
            return false;
        }

        switch (registration.Kind)
        {
            case AgentTelemetryAuditArtifactKind.File:
                try
                {
                    var path = Path.GetFullPath(registration.Target);
                    var relative = Path.GetRelativePath(_labRoot, path);
                    if (!Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar) &&
                        Path.GetFileName(path).StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) return true;
                }
                catch
                {
                }
                break;
            case AgentTelemetryAuditArtifactKind.RegistryKey:
                if (registration.Target.StartsWith("HKCU\\Software\\ProcInsiderTest_", StringComparison.OrdinalIgnoreCase) &&
                    !registration.Target["HKCU\\Software\\".Length..].Contains('\\')) return true;
                break;
            case AgentTelemetryAuditArtifactKind.LocalUser:
            case AgentTelemetryAuditArtifactKind.LocalGroup:
                if (registration.Target.StartsWith(Environment.MachineName + "\\ProcInsiderTest_", StringComparison.OrdinalIgnoreCase) &&
                    registration.Target.Count(character => character == '\\') == 1) return true;
                break;
            case AgentTelemetryAuditArtifactKind.CngKey:
                if (registration.Target.StartsWith("ProcInsiderTest_AuditKey_", StringComparison.Ordinal) &&
                    string.Equals(registration.Target, registration.OwnershipMarker, StringComparison.Ordinal)) return true;
                break;
        }

        error = "The durable cleanup target is outside the exact Agent audit allowlist.";
        return false;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        public IntPtr Name;
        public IntPtr Password;
        public uint PasswordAge;
        public uint Privilege;
        public IntPtr HomeDirectory;
        public IntPtr CommentPointer;
        public uint Flags;
        public IntPtr ScriptPath;

        public string? Comment => Marshal.PtrToStringUni(CommentPointer);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LocalGroupInfo1
    {
        public IntPtr Name;
        public IntPtr CommentPointer;

        public string? Comment => Marshal.PtrToStringUni(CommentPointer);
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserDel(string? serverName, string userName);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserGetInfo(string? serverName, string userName, uint level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupDel(string? serverName, string groupName);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupGetInfo(string? serverName, string groupName, uint level, out IntPtr buffer);

    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);
}
