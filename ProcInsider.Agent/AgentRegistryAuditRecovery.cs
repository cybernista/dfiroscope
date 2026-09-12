using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed partial class AgentObjectAccessAuditingService
{
    private T WithPrivilege<T>(Func<T> action)
    {
        using var lease = _registryHistory.Enter();
        return _runtime.WithPrivilege(action);
    }

    private static string ExpectedIdentity(ObjectAuditEntry entry) =>
        entry.CurrentIdentity.Length == 0 ? entry.Identity : entry.CurrentIdentity;

    private static ObjectAuditTarget EffectiveTarget(ObjectAuditTarget target, ObjectAuditJournal journal)
    {
        if (target.Kind != ObjectAuditKind.RegistryKey || target.Root.Length == 0) return target;
        var root = journal.Entries.SingleOrDefault(e => e.Target.Kind == ObjectAuditKind.RegistryKey &&
            e.Target.Path.Equals(target.Root, StringComparison.OrdinalIgnoreCase));
        // Root rebinding comes only from this protected journal, never from discovered/path-only state.
        return root == null ? target : target with { RootIdentity = ExpectedIdentity(root) };
    }

    private static void RequireVerifiedCurrent(ObjectAuditEntry entry, ObjectAuditSnapshot current, bool restoringRootSettings = false)
    {
        var restoreRegistryPath = restoringRootSettings && entry.Target.RootConfigurationOnly && entry.Target.Kind == ObjectAuditKind.RegistryKey;
        if (current.Identity != ExpectedIdentity(entry) || (!restoreRegistryPath && current.Sacl != entry.Before && current.Sacl != entry.After))
            throw new InvalidOperationException("Object or SACL changed outside a verified Agent transition; no write attempted.");
        if (entry.PendingRegistryWrite is { } pending &&
            (current.Identity != pending.Identity || current.Sacl != pending.Sacl))
            throw new InvalidOperationException("Registry write was interrupted without a verified identity transition; manual recovery review required.");
    }

    private void WriteAndVerify(ObjectAuditEntry originalEntry, string desired, IObjectAuditHandle handle, ref ObjectAuditJournal journal,
        List<string>? recoveryWarnings = null, bool restoringRootSettings = false)
    {
        var entry = journal.Entries.SingleOrDefault(e => ObjectAuditTargetComparer.Instance.Equals(e.Target, originalEntry.Target)) ?? originalEntry;
        var before = handle.Read();
        RequireVerifiedCurrent(entry, before, restoringRootSettings);
        if (restoringRootSettings && entry.Target.RootConfigurationOnly && entry.Target.Kind == ObjectAuditKind.RegistryKey)
            ValidateSettingsSacl(before.Sacl, desired, entry.Target.IncludeDescendants);
        var registry = entry.Target.Kind == ObjectAuditKind.RegistryKey && handle.SupportsRegistryIdentityTransitions;
        if (before.Sacl == desired)
        {
            if (entry.PendingRegistryWrite != null) PersistEntry(entry with { PendingRegistryWrite = null }, ref journal);
            return;
        }
        if (registry)
        {
            UpdateHistory(() => _registryHistory.CheckCapacity(entry.Target.Path, before.Identity), recoveryWarnings);
            entry = entry with { PendingRegistryWrite = new(before.Identity, before.Sacl, desired) };
            PersistEntry(entry, ref journal); // Original and uncertainty durable before touching Windows.
        }
        handle.WriteSacl(desired);
        var after = handle.Read();
        if (after.Sacl != desired || (registry ? !handle.IsSameRegistryObject(before, after) : after.Identity != before.Identity))
            throw new InvalidOperationException("Post-write verification differs; original state and pending recovery retained.");
        if (registry)
        {
            // Journal commits first. A crash before this point cannot infer success from path/SACL.
            // History is secondary: failure there cannot erase the exact current recovery identity.
            PersistEntry(entry with { CurrentIdentity = after.Identity, PendingRegistryWrite = null }, ref journal);
            UpdateHistory(() => _registryHistory.Record(entry.Target.Path, before.Identity, after.Identity), recoveryWarnings);
        }
    }

    private static void UpdateHistory(Action update, List<string>? recoveryWarnings)
    {
        try { update(); }
        catch (Exception ex) when (recoveryWarnings != null && (IsTargetFailure(ex) || ex is System.Text.Json.JsonException))
        {
            recoveryWarnings.Add("Saved-export registry identity history could not be updated. Exact protected-journal recovery " +
                "remains available, but older exports may no longer load. " + ex.Message);
        }
    }

    private void PersistEntry(ObjectAuditEntry entry, ref ObjectAuditJournal journal)
    {
        var updated = journal with { Version = journal.Version == 3 ? 3 : 2, Entries = journal.Entries.Select(e =>
            ObjectAuditTargetComparer.Instance.Equals(e.Target, entry.Target) ? entry : e).ToArray() };
        if (!updated.Entries.Any(e => e == entry)) throw new InvalidOperationException("Registry write has no durable original entry.");
        _store.Write(updated);
        journal = updated;
        _journalRequired = true;
    }

    internal bool SettingsMatch(ObjectAuditingSettings expected, ObjectAuditingSettings actual, bool registry)
    {
        using var lease = _registryHistory.Enter();
        return expected.RootConfigurationOnly == actual.RootConfigurationOnly && expected.Entries.Length == actual.Entries.Length && expected.Entries.All(saved =>
            actual.Entries.Any(current => current.Path.Equals(saved.Path, StringComparison.OrdinalIgnoreCase) &&
                current.Sacl == saved.Sacl && (current.Identity == saved.Identity ||
                    (registry && _registryHistory.Matches(current.Path, saved.Identity, current.Identity)))));
    }
}
