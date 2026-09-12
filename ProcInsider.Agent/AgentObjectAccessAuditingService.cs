using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ProcInsider.Models.Agent;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.Agent;

internal enum ObjectAuditKind { Directory = 1, RegistryKey = 2, File = 3 }
internal sealed record ObjectAuditTarget(ObjectAuditKind Kind, string Path)
{
    public string Root { get; init; } = string.Empty;
    public string RootIdentity { get; init; } = string.Empty;
    public bool IncludeDescendants { get; init; } = true;
    public bool RootConfigurationOnly { get; init; }
}
internal sealed class ObjectAuditTargetComparer : IEqualityComparer<ObjectAuditTarget>
{
    internal static readonly ObjectAuditTargetComparer Instance = new();
    public bool Equals(ObjectAuditTarget? left, ObjectAuditTarget? right) => left?.Kind == right?.Kind &&
        StringComparer.OrdinalIgnoreCase.Equals(left?.Path, right?.Path);
    public int GetHashCode(ObjectAuditTarget target) => HashCode.Combine(target.Kind, StringComparer.OrdinalIgnoreCase.GetHashCode(target.Path));
}
internal sealed record ObjectAuditDiscovery(ObjectAuditTarget[] Targets, string[] Gaps)
{
    public string[] Exclusions { get; init; } = [];
}
internal sealed record ObjectAuditSnapshot(string Identity, string Sacl);
internal sealed record ObjectAuditEntry(ObjectAuditTarget Target, string Identity, string Before, string After)
{
    public bool IsSettingsLoad { get; init; }
    public string CurrentIdentity { get; init; } = string.Empty;
    public RegistryAuditPendingWrite? PendingRegistryWrite { get; init; }
}
internal sealed record RegistryAuditPendingWrite(string Identity, string Sacl, string DesiredSacl);
internal sealed record ObjectAuditPlan(ObjectAuditEntry[] Entries, string[] Gaps, string ConfigurationHash)
{
    public IReadOnlyDictionary<string, string>? RootSettingsValues { get; init; }
}
internal sealed record ObjectAuditJournal(int Version, string Scope, ObjectAuditEntry[] Entries)
{
    public string PortableBackupId { get; init; } = string.Empty;
}
internal sealed record ObjectAuditResult(int Verified, string[] Gaps)
{
    public bool RootConfigurationOnly { get; init; }
    public string[] Roots { get; init; } = [];
    public string[] CompatibilityWarnings { get; init; } = [];
    public string Detail => RootConfigurationOnly ? $"Object auditing: {Verified} roots verified. Windows handles inheritance; descendant coverage was not individually verified. " +
        string.Join("\n", Gaps) : $"Object auditing: {Verified} objects verified. " +
        "Only verified journaled objects are restored; future/moved objects and protected/inaccessible descendants require separate coverage review. " +
        "Roots: " + string.Join("; ", Roots.Take(12)) + (Roots.Length > 12 ? $"; {Roots.Length - 12} more roots" : "") + ". " +
        string.Join(" | ", Gaps.Take(12)) + (Gaps.Length > 12 ? $" | {Gaps.Length - 12} additional gaps omitted from this summary." : "") +
        string.Join(" | ", CompatibilityWarnings);
}

internal interface IObjectAuditHandle : IDisposable
{
    ObjectAuditSnapshot Read();
    void WriteSacl(string sacl);
    bool SupportsRegistryIdentityTransitions => false;
    bool IsSameRegistryObject(ObjectAuditSnapshot before, ObjectAuditSnapshot after) => false;
}

internal interface IObjectAuditRuntime
{
    bool RootConfigurationOnly => false;
    T WithPrivilege<T>(Func<T> action);
    ObjectAuditDiscovery Discover(AgentSecurityAuditMonitoringIntent intent);
    ObjectAuditDiscovery DiscoverLegacy(AgentSecurityAuditMonitoringIntent intent) => Discover(intent);
    ObjectAuditDiscovery DiscoverUnderRoots(ObjectAuditTarget[] roots);
    IObjectAuditHandle Open(ObjectAuditTarget target);
}

internal interface IObjectAuditJournalStore
{
    ObjectAuditJournal? Read();
    void Write(ObjectAuditJournal journal);
}

/// <summary>
/// Owns the additive SACL plan and recovery journal. It never changes access permissions or
/// starts evidence capture. The caller uses the existing serialized Agent monitoring boundary.
/// </summary>
internal sealed partial class AgentObjectAccessAuditingService
{
    internal const int MaxTargets = 8192;
    internal const int FileWriteMask = 0xD0156; // write/append/EA/attributes/delete-child/delete/DACL/owner
    internal const int RegistryWriteMask = 0xD0006; // set-value/create-subkey/delete/DACL/owner
    private readonly IObjectAuditRuntime _runtime;
    private readonly IObjectAuditJournalStore _store;
    private readonly string _scope;
    private readonly RegistryAuditIdentityHistoryStore _registryHistory;
    private bool _journalRequired;

    public AgentObjectAccessAuditingService(InvestigationSessionPaths paths)
        : this(new WindowsObjectAuditRuntime(), new ObjectAuditJournalFile(paths), ObjectAuditJournalFile.Scope(paths)) { }

    internal AgentObjectAccessAuditingService(IObjectAuditRuntime runtime, IObjectAuditJournalStore store, string scope,
        RegistryAuditIdentityHistoryStore? registryHistory = null)
    {
        _runtime = runtime;
        _store = store;
        _scope = scope;
        _registryHistory = registryHistory ?? (store is ObjectAuditJournalFile file ? file.RegistryHistory : RegistryAuditIdentityHistoryStore.ForFixture(store));
    }

    internal static bool Requested(AgentSecurityAuditMonitoringIntent intent) =>
        intent.AuditUserDataFolders || intent.AuditRegistryWrites;

    internal static void ValidateIntent(AgentSecurityAuditMonitoringIntent intent)
    {
        if (Requested(intent) && !intent.ConfigureAuditPolicy)
            throw new InvalidOperationException("Object auditing requires Configure audit policy.");
    }

    internal ObjectAuditingSettings ExportSettings(bool registry, bool rootConfiguration = true) => WithPrivilege(() =>
    {
        var intent = new AgentSecurityAuditMonitoringIntent { ConfigureAuditPolicy = true, AuditRegistryWrites = registry, AuditUserDataFolders = !registry };
        var rootMode = rootConfiguration && _runtime.RootConfigurationOnly;
        var discovery = rootConfiguration ? _runtime.Discover(intent) : _runtime.DiscoverLegacy(intent);
        if (!rootMode && discovery.Gaps.Length > 0) throw new InvalidOperationException("Incomplete object coverage; area not exported: " + string.Join("; ", discovery.Gaps.Take(3)));
        if (discovery.Targets.Length > MaxTargets) throw new InvalidOperationException("Object export bound exceeded.");
        var entries = new List<ObjectAuditingSetting>();
        var exclusions = discovery.Exclusions.ToList();
        if (rootMode) exclusions.AddRange(discovery.Gaps);
        foreach (var target in discovery.Targets)
        {
            try
            {
                using var handle = _runtime.Open(target);
                var observed = handle.Read();
                entries.Add(new ObjectAuditingSetting(target.Path, observed.Identity, observed.Sacl));
            }
            catch (Exception ex) when (WindowsObjectAuditRuntime.IsAbsentTarget(ex))
            { exclusions.Add($"{target.Path}: not present; not created or changed."); }
            catch (Exception ex) when (rootMode && IsTargetFailure(ex))
            { exclusions.Add($"{target.Path}: backup failed: {ex.Message}"); }
        }
        return new ObjectAuditingSettings(entries.ToArray()) { RootConfigurationOnly = rootMode,
            ScopeNotes = exclusions.Take(127).Select(n => n[..Math.Min(n.Length, 2048)]).ToArray() };
    });

    internal ObjectAuditPlan PrepareSettings(WindowsSecuritySettingsSnapshot snapshot, string hash) => WithPrivilege(() =>
    {
        snapshot.Validate();
        var journal = ReadJournal();
        var intent = new AgentSecurityAuditMonitoringIntent { ConfigureAuditPolicy = true,
            AuditUserDataFolders = snapshot.UserFolderAuditing != null, AuditRegistryWrites = snapshot.RegistryAuditing != null };
        var rootMode = snapshot.Version == 2;
        if (rootMode) return PrepareRootSettings(snapshot, hash, journal, _runtime.Discover(intent));
        if (journal.Entries.Any(e => e.Target.RootConfigurationOnly))
            throw new InvalidOperationException("Restore the active root baseline before loading a legacy per-object snapshot.");
        var discovery = _runtime.DiscoverLegacy(intent);
        if (discovery.Gaps.Length > 0) throw new InvalidOperationException("Object load requires complete verified coverage: " + string.Join("; ", discovery.Gaps.Take(3)));
        var saved = (snapshot.UserFolderAuditing?.Entries ?? []).Concat(snapshot.RegistryAuditing?.Entries ?? []).ToArray();
        var liveTargets = discovery.Targets.ToDictionary(t => t.Path, StringComparer.OrdinalIgnoreCase);
        if (saved.Length != liveTargets.Count || saved.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != saved.Length)
            throw new InvalidOperationException("The saved object inventory differs from this computer; no SACL changes were attempted.");
        var entries = new List<ObjectAuditEntry>();
        foreach (var setting in saved)
        {
            // Only independently rediscovered targets reach privileged Open, never file-supplied paths.
            if (!liveTargets.TryGetValue(setting.Path, out var target) ||
                (snapshot.RegistryAuditing?.Entries.Contains(setting) == true) != (target.Kind == ObjectAuditKind.RegistryKey))
                throw new InvalidOperationException("Saved object is outside the selected verified area.");
            using var handle = _runtime.Open(target);
            var current = handle.Read();
            if (!(current.Identity == setting.Identity || (target.Kind == ObjectAuditKind.RegistryKey &&
                _registryHistory.Matches(target.Path, setting.Identity, current.Identity))))
                throw new InvalidOperationException("A saved object was replaced or changed identity without a verified Agent transition.");
            ValidateSettingsSacl(current.Sacl, setting.Sacl, target.IncludeDescendants);
            var prior = journal.Entries.SingleOrDefault(e => ObjectAuditTargetComparer.Instance.Equals(e.Target, target));
            if (prior == null && UnknownAuditRequiresReview(target, current.Sacl, journal))
                throw new InvalidOperationException("An unjournaled object has unknown audit ownership under an active baseline; loading cannot adopt it.");
            var entry = new ObjectAuditEntry(target, current.Identity, current.Sacl, setting.Sacl) { IsSettingsLoad = true };
            if (prior != null)
            {
                RequireVerifiedCurrent(prior, current);
                if (ExpectedIdentity(prior) != current.Identity || EffectiveTarget(prior.Target, journal) != target || prior.After != setting.Sacl ||
                    (current.Sacl != prior.Before && current.Sacl != prior.After))
                    throw new InvalidOperationException("Restore or review the active object-audit baseline before loading different SACL settings.");
                entry = prior;
            }
            entries.Add(entry);
        }
        return new ObjectAuditPlan(entries.ToArray(), [], hash);
    });

    private ObjectAuditPlan PrepareRootSettings(WindowsSecuritySettingsSnapshot snapshot, string hash,
        ObjectAuditJournal journal, ObjectAuditDiscovery discovery)
    {
        if (journal.Entries.Any(e => !e.Target.RootConfigurationOnly))
            throw new InvalidOperationException("Restore the existing per-object audit baseline before loading root settings.");
        var entries = new List<ObjectAuditEntry>();
        var gaps = discovery.Gaps.Concat(discovery.Exclusions).ToList();
        var desired = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var setting in (snapshot.UserFolderAuditing?.Entries ?? []).Concat(snapshot.RegistryAuditing?.Entries ?? []))
        {
            var target = discovery.Targets.SingleOrDefault(t => t.Path.Equals(setting.Path, StringComparison.OrdinalIgnoreCase));
            if (target == null || !target.RootConfigurationOnly ||
                (snapshot.RegistryAuditing?.Entries.Contains(setting) == true) != (target.Kind == ObjectAuditKind.RegistryKey))
            { gaps.Add($"{setting.Path}: saved root is unavailable or outside the selected root policy; not changed."); continue; }
            try
            {
                using var handle = _runtime.Open(target);
                var current = handle.Read();
                if (!(current.Identity == setting.Identity || target.Kind == ObjectAuditKind.RegistryKey &&
                    _registryHistory.Matches(target.Path, setting.Identity, current.Identity)))
                    throw new InvalidOperationException("Saved root identity changed; not restored.");
                ValidateSettingsSacl(current.Sacl, setting.Sacl, target.IncludeDescendants);
                var prior = journal.Entries.SingleOrDefault(e => ObjectAuditTargetComparer.Instance.Equals(e.Target, target));
                if (prior != null)
                {
                    RequireVerifiedCurrent(prior, current, restoringRootSettings: true);
                    if (setting.Sacl != prior.Before && setting.Sacl != prior.After)
                        throw new InvalidOperationException("Resolve the active root baseline before loading different settings.");
                }
                entries.Add(prior ?? new(target, current.Identity, current.Sacl, setting.Sacl) { IsSettingsLoad = true });
                desired.Add(target.Path, setting.Sacl);
            }
            catch (Exception ex) when (IsTargetFailure(ex)) { gaps.Add($"{setting.Path}: {ex.Message}"); }
        }
        return new(entries.ToArray(), gaps.ToArray(), hash) { RootSettingsValues = desired };
    }

    private static void ValidateSettingsSacl(string before, string after, bool includeDescendants)
    {
        var original = new RawSecurityDescriptor(before);
        var desired = new RawSecurityDescriptor(after);
        if (desired.Owner != null || desired.Group != null || desired.DiscretionaryAcl != null ||
            (desired.ControlFlags & ~ControlFlags.SystemAclPresent) != (original.ControlFlags & ~ControlFlags.SystemAclPresent) ||
            desired.GetSddlForm(AccessControlSections.Audit) != after)
            throw new InvalidOperationException("Saved settings must contain only a canonical SACL and preserve protection/inheritance semantics.");
        if (!includeDescendants)
        {
            static string InheritableEntries(RawSecurityDescriptor descriptor) => string.Join(";",
                descriptor.SystemAcl?.Cast<GenericAce>().Where(ace =>
                    (ace.AceFlags & (AceFlags.ContainerInherit | AceFlags.ObjectInherit)) != 0).Select(ace =>
                    {
                        var bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0); return Convert.ToHexString(bytes);
                    }) ?? []);
            if (InheritableEntries(original) != InheritableEntries(desired))
                throw new InvalidOperationException("This bounded root excludes descendants; loading cannot change inheritable audit entries outside its scope.");
        }
    }

    internal ObjectAuditPlan Prepare(AgentSecurityAuditMonitoringIntent intent, string configurationHash,
        WindowsSecuritySettingsSnapshot? savedBackup = null)
    {
        ValidateIntent(intent);
        if (!Requested(intent)) return new([], [], configurationHash);
        return WithPrivilege(() =>
        {
            var retained = ReadJournal();
            if (_runtime.RootConfigurationOnly && retained.Entries.Any(e => !e.Target.RootConfigurationOnly))
                throw new InvalidOperationException("Restore the existing per-object audit baseline before applying root configuration.");
            var discovery = _runtime.Discover(intent);
            if (discovery.Targets.Length > MaxTargets)
                throw new InvalidOperationException($"Object auditing is limited to {MaxTargets} objects per deployment.");
            var entries = new List<ObjectAuditEntry>();
            var gaps = discovery.Gaps.Concat(discovery.Exclusions).ToList();
            foreach (var target in discovery.Targets.Distinct(ObjectAuditTargetComparer.Instance))
            {
                if (target.Kind == ObjectAuditKind.RegistryKey && WindowsObjectAuditTargets.IsReservedCommandLinePolicyPath(target.Path))
                {
                    gaps.Add($"{target.Path}: reserved Agent command-line policy subtree; object auditing excluded.");
                    continue;
                }
                try
                {
                    using var handle = _runtime.Open(target);
                    var current = handle.Read();
                    if (savedBackup != null && target.RootConfigurationOnly)
                    {
                        var settings = target.Kind == ObjectAuditKind.RegistryKey ? savedBackup.RegistryAuditing : savedBackup.UserFolderAuditing;
                        var saved = settings?.Entries.SingleOrDefault(e => e.Path.Equals(target.Path, StringComparison.OrdinalIgnoreCase));
                        if (settings?.RootConfigurationOnly != true || saved == null || saved.Sacl != current.Sacl ||
                            !(saved.Identity == current.Identity || target.Kind == ObjectAuditKind.RegistryKey && _registryHistory.Matches(target.Path, saved.Identity, current.Identity)))
                        { gaps.Add($"{target.Path}: skipped because no matching readable original was saved; save again."); continue; }
                    }
                    var previous = retained.Entries.SingleOrDefault(e => ObjectAuditTargetComparer.Instance.Equals(e.Target, target));
                    if (previous == null && UnknownAuditRequiresReview(target, current.Sacl, retained))
                    {
                        gaps.Add($"{target.Path}: unjournaled audit ownership under an active baseline; manual recovery review required before reapply.");
                        continue;
                    }
                    if (previous != null &&
                        (ExpectedIdentity(previous) != current.Identity || EffectiveTarget(previous.Target, retained).RootIdentity != target.RootIdentity ||
                         !StringComparer.OrdinalIgnoreCase.Equals(previous.Target.Root, target.Root) ||
                         previous.Target.IncludeDescendants != target.IncludeDescendants ||
                         (current.Sacl != previous.After && current.Sacl != previous.Before)))
                    {
                        gaps.Add($"{target.Path}: active SACL or object identity changed; restore/review before reapplying.");
                        continue;
                    }
                    if (previous != null) RequireVerifiedCurrent(previous, current);
                    entries.Add(previous ?? new(target, current.Identity, current.Sacl,
                        AddWriteAudit(current.Sacl, target.Kind, target.IncludeDescendants)));
                }
                catch (Exception ex) when (IsTargetFailure(ex)) { gaps.Add($"{target.Path}: {ex.Message}"); }
            }
            return new ObjectAuditPlan(entries.ToArray(), gaps.ToArray(), configurationHash);
        });
    }

    internal ObjectAuditResult Check(AgentSecurityAuditMonitoringIntent intent)
    {
        var plan = Prepare(intent, string.Empty);
        return WithPrivilege(() =>
        {
            var gaps = plan.Gaps.ToList();
            var verified = 0;
            // The read-only pass holds the operation lease. Validate the protected journal
            // once, not once per object (each read decrypts and validates every entry).
            var journal = ReadJournal();
            foreach (var entry in plan.Entries)
            {
                try
                {
                    using var handle = _runtime.Open(EffectiveTarget(entry.Target, journal));
                    var current = handle.Read();
                    RequireVerifiedCurrent(entry, current);
                    if (current.Identity == ExpectedIdentity(entry) &&
                        AddWriteAudit(current.Sacl, entry.Target.Kind, entry.Target.IncludeDescendants) == current.Sacl)
                        verified++;
                    else gaps.Add($"{entry.Target.Path}: requested write-auditing SACL is not effective.");
                }
                catch (Exception ex) when (IsTargetFailure(ex)) { gaps.Add($"{entry.Target.Path}: {ex.Message}"); }
            }
            return new ObjectAuditResult(verified, gaps.ToArray()) { RootConfigurationOnly = _runtime.RootConfigurationOnly, Roots = plan.Entries.Select(e => RootOf(e.Target).Path).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() };
        });
    }

    internal ObjectAuditResult Deploy(ObjectAuditPlan plan) => WithPrivilege(() =>
    {
        var journal = ReadJournal();
        var retained = journal.Entries.ToDictionary(e => e.Target, ObjectAuditTargetComparer.Instance);
        var gaps = plan.Gaps.ToList();
        var verified = 0;
        if (plan.Entries.Any(e => e.Before != e.After))
        {
            // Retain unchanged baseline nodes too: without them a later scan cannot distinguish
            // the original tree from unjournaled descendants. Publish one bounded plan first.
            foreach (var entry in plan.Entries)
            {
                if (retained.TryGetValue(entry.Target, out var prior) && prior != entry)
                    throw new InvalidOperationException("Conflicting active restoration baseline.");
                retained[entry.Target] = entry;
            }
            if (retained.Count > MaxTargets) throw new InvalidOperationException("Recovery journal object limit reached.");
            journal = new(retained.Values.Any(e => e.Target.RootConfigurationOnly) ? 3 : 2, _scope, retained.Values.ToArray());
            _store.Write(journal);
            _journalRequired = true;
        }

        // Dependency state comes from the complete retained recovery obligation, not
        // only the entries that survived this Prepare call. A drifted/unreadable parent
        // is deliberately omitted from a new plan but must still block its pending child.
        var dependencyEntries = retained.Values.ToArray();
        var entriesByPath = EntriesByPath(dependencyEntries);
        var preflight = new Dictionary<ObjectAuditTarget, ObjectAuditSnapshot>(ObjectAuditTargetComparer.Instance);
        var failed = new HashSet<ObjectAuditTarget>(ObjectAuditTargetComparer.Instance);
        var blockedAncestors = new Dictionary<ObjectAuditTarget, ObjectAuditTarget>(ObjectAuditTargetComparer.Instance);
        var plannedTargets = plan.Entries.Select(e => e.Target).ToHashSet(ObjectAuditTargetComparer.Instance);

        void BlockAncestors(ObjectAuditEntry entry)
        {
            foreach (var ancestor in AncestorsOf(entry, entriesByPath).Where(e => e.Before != e.After))
                blockedAncestors.TryAdd(ancestor.Target, entry.Target);
        }

        void MarkFailed(ObjectAuditEntry entry)
        {
            failed.Add(entry.Target);
            BlockAncestors(entry);
        }

        // Re-read the complete journaled transition before writing. This also identifies a
        // retained partial deployment whose parent inheritance source is already active.
        foreach (var entry in dependencyEntries)
        {
            using var handle = OpenOrGap(EffectiveTarget(entry.Target, journal), gaps);
            if (handle == null) { MarkFailed(entry); continue; }
            try
            {
                var current = handle.Read();
                RequireVerifiedCurrent(entry, current, restoringRootSettings: plan.RootSettingsValues != null);
                preflight[entry.Target] = current;
            }
            catch (Exception ex) when (IsTargetFailure(ex))
            {
                gaps.Add($"{entry.Target.Path}: {ex.Message}");
                MarkFailed(entry);
            }
        }

        foreach (var entry in dependencyEntries.Where(e => !plannedTargets.Contains(e.Target) && !failed.Contains(e.Target) &&
                     e.Before != e.After && preflight[e.Target].Sacl == e.Before))
        {
            gaps.Add($"{entry.Target.Path}: retained pending object is absent from the current plan; dependent ancestor activation withheld.");
            BlockAncestors(entry);
        }

        foreach (var entry in plan.Entries.Where(e => !failed.Contains(e.Target) && e.Before != e.After &&
                     preflight[e.Target].Sacl == e.Before))
        {
            var unsafeAncestor = AncestorsOf(entry, entriesByPath).FirstOrDefault(ancestor =>
                failed.Contains(ancestor.Target) ||
                (ancestor.Before != ancestor.After && preflight.TryGetValue(ancestor.Target, out var state) && state.Sacl == ancestor.After));
            if (unsafeAncestor == null) continue;
            gaps.Add($"{entry.Target.Path}: managed ancestor {unsafeAncestor.Target.Path} is active or unverified; " +
                "restore the retained baseline before reapplying this descendant.");
            MarkFailed(entry);
        }

        // Apply descendants before their inheritance sources. Otherwise Windows can
        // materialize a newly added parent audit ACE while a child's SACL is written,
        // making that child differ from its pre-journaled transition. The native write
        // itself remains non-recursive and every object is still verified separately.
        foreach (var entry in plan.Entries.OrderByDescending(EntryDepth))
        {
            if (failed.Contains(entry.Target)) continue;
            if (blockedAncestors.TryGetValue(entry.Target, out var failedDescendant))
            {
                gaps.Add($"{entry.Target.Path}: deployment withheld because descendant {failedDescendant.Path} was not safely verified.");
                failed.Add(entry.Target);
                continue;
            }
            using var handle = OpenOrGap(EffectiveTarget(entry.Target, journal), gaps);
            if (handle == null) { MarkFailed(entry); continue; }
            try
            {
                WriteAndVerify(entry, plan.RootSettingsValues?.GetValueOrDefault(entry.Target.Path, entry.After) ?? entry.After, handle, ref journal,
                    restoringRootSettings: plan.RootSettingsValues != null);
                verified++;
            }
            catch (Exception ex) when (IsTargetFailure(ex))
            {
                gaps.Add($"{entry.Target.Path}: {ex.Message}");
                MarkFailed(entry);
            }
        }
        return new ObjectAuditResult(verified, gaps.ToArray()) { RootConfigurationOnly = journal.Version == 3 || plan.Entries.Any(e => e.Target.RootConfigurationOnly), Roots = plan.Entries.Select(e => RootOf(e.Target).Path).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() };
    });

    internal ObjectAuditResult Restore() => WithPrivilege(() =>
    {
        var journal = ReadJournal();
        var gaps = new List<string>();
        var compatibilityWarnings = new List<string>();
        var verified = 0;
        var roots = journal.Entries.Select(e => RootOf(e.Target)).Distinct().ToArray();
        var known = journal.Entries.Select(e => e.Target).ToHashSet(ObjectAuditTargetComparer.Instance);
        void CheckUnjournaledDescendants()
        {
            if (journal.Version == 3) return;
            var currentTree = _runtime.DiscoverUnderRoots(roots.Select(root => EffectiveTarget(root, journal)).ToArray());
            gaps.AddRange(currentTree.Gaps);
            foreach (var unknown in currentTree.Targets.Where(t => !known.Contains(t)))
            {
                using var handle = OpenOrGap(unknown, gaps);
                if (handle == null) continue;
                try
                {
                    if (UnknownAuditRequiresReview(unknown, handle.Read().Sacl, journal))
                        gaps.Add($"{unknown.Path}: unjournaled audit ownership is unknown. Manual recovery review required.");
                }
                catch (Exception ex) when (IsTargetFailure(ex)) { gaps.Add($"{unknown.Path}: {ex.Message}"); }
            }
        }
        CheckUnjournaledDescendants();
        // Remove verified inheritable contributions on ancestors first. Each native write is
        // non-recursive; existing children and unrelated SACLs are never implicitly rewritten.
        var entriesByPath = EntriesByPath(journal.Entries);
        var failedAncestors = new HashSet<ObjectAuditTarget>(ObjectAuditTargetComparer.Instance);
        foreach (var entry in journal.Entries.OrderBy(EntryDepth))
        {
            var failedAncestor = AncestorsOf(entry, entriesByPath).FirstOrDefault(e => failedAncestors.Contains(e.Target));
            if (failedAncestor != null)
            {
                gaps.Add($"{entry.Target.Path}: restoration withheld because ancestor {failedAncestor.Target.Path} was not restored.");
                continue;
            }
            using var handle = OpenOrGap(EffectiveTarget(entry.Target, journal), gaps);
            if (handle == null) { failedAncestors.Add(entry.Target); continue; }
            try
            {
                WriteAndVerify(entry, entry.Before, handle, ref journal, compatibilityWarnings, restoringRootSettings: journal.Version == 3);
                verified++;
            }
            catch (Exception ex) when (IsTargetFailure(ex))
            {
                gaps.Add($"{entry.Target.Path}: {ex.Message}");
                failedAncestors.Add(entry.Target);
            }
        }
        // Keep the entire original tree/obligation after a partial recovery, even if all known
        // ACEs were restored. A later retry must still surface unresolved new descendants.
        // Re-scan after removing inheritance sources: a child created during the first scan
        // must not disappear from recovery accounting merely because it was not observed yet.
        CheckUnjournaledDescendants();
        if (gaps.Count == 0) _store.Write(new(journal.Version == 3 ? 3 : 2, _scope, []));
        return new ObjectAuditResult(verified, gaps.Distinct().ToArray())
        { RootConfigurationOnly = journal.Version == 3, Roots = roots.Select(e => e.Path).ToArray(), CompatibilityWarnings = compatibilityWarnings.Distinct().ToArray() };
    });

    internal bool HasPendingRestore => ReadJournal().Entries.Length > 0;

    private static bool UnknownAuditRequiresReview(ObjectAuditTarget target, string sacl, ObjectAuditJournal journal)
    {
        var roots = journal.Entries.Where(e =>
            ObjectAuditTargetComparer.Instance.Equals(RootOf(e.Target), RootOf(target)) ||
            target.Path.StartsWith(RootOf(e.Target).Path.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)).ToArray();
        return roots.Length > 0 && (roots.Any(e => e.IsSettingsLoad) || (target.Kind == ObjectAuditKind.RegistryKey
            ? new RawSecurityDescriptor(sacl).SystemAcl?.Count > 0
            : HasInheritedWriteAudit(sacl, target.Kind)));
    }

    internal bool HasRecoveryJournal
    {
        get
        {
            return TryGetRecoveryJournalEntryCount(out _);
        }
    }

    internal bool TryGetRecoveryJournalEntryCount(out int entryCount)
    {
        var journal = _store.Read();
        if (journal == null)
        {
            if (_journalRequired)
                throw new InvalidOperationException("Expected object-auditing recovery journal is missing; deployment/restoration withheld.");
            entryCount = 0;
            return false;
        }
        _journalRequired = true;
        ValidateJournal(journal);
        entryCount = journal.Entries.Length;
        return true;
    }

    internal void EnsureNoCommandLinePolicyConflict()
    {
        if (ReadJournal().Entries.Any(e => e.Target.Kind == ObjectAuditKind.RegistryKey &&
            WindowsObjectAuditTargets.IsReservedCommandLinePolicyPath(e.Target.Path)))
            throw new InvalidOperationException("An active object-audit baseline covers the command-line policy subtree; restore/review that baseline before changing command-line policy.");
    }

    internal void RequireRecoveryJournal()
    {
        _journalRequired = true;
        _ = ReadJournal();
    }

    internal void InitializeRecoveryJournal()
    {
        using var lease = _registryHistory.Enter();
        _store.Write(ReadJournal());
        _journalRequired = true;
    }

    private ObjectAuditJournal ReadJournal()
    {
        var journal = _store.Read();
        if (journal == null && _journalRequired)
            throw new InvalidOperationException("Expected object-auditing recovery journal is missing; deployment/restoration withheld.");
        if (journal != null) _journalRequired = true;
        journal ??= new ObjectAuditJournal(1, _scope, []);
        ValidateJournal(journal);
        return journal;
    }

    private void ValidateJournal(ObjectAuditJournal journal)
    {
        if (journal.Version is not (1 or 2 or 3) || journal.Scope != _scope || journal.Entries == null ||
            journal.Entries.Length > MaxTargets || journal.Entries.Any(e => e == null || e.Target == null ||
                !Enum.IsDefined(e.Target.Kind) || string.IsNullOrWhiteSpace(e.Target.Path) || e.Target.Path.Length > 4096 ||
                string.IsNullOrWhiteSpace(e.Identity) || e.Identity.Length > 4096 ||
                e.Target.Root == null || e.Target.Root.Length > 4096 ||
                e.Target.RootIdentity == null || e.Target.RootIdentity.Length > 4096 ||
                e.Before == null || e.After == null || e.Before.Length > 131072 || e.After.Length > 131072) ||
            journal.Entries.Select(e => e.Target).Distinct(ObjectAuditTargetComparer.Instance).Count() != journal.Entries.Length)
            throw new InvalidOperationException("Object-auditing recovery journal is invalid or belongs to another session/host.");
        foreach (var entry in journal.Entries)
        {
            if (entry.Target.RootConfigurationOnly != (journal.Version == 3) ||
                entry.Target.RootConfigurationOnly && (entry.Target.Kind == ObjectAuditKind.File ||
                    !entry.Target.Path.Equals(entry.Target.Root, StringComparison.OrdinalIgnoreCase) || entry.Target.RootIdentity != entry.Identity))
                throw new InvalidOperationException("Audit journal mode/version or root identity is invalid.");
            if (entry.CurrentIdentity == null || entry.CurrentIdentity.Length > 4096 ||
                ((entry.CurrentIdentity.Length > 0 || entry.PendingRegistryWrite != null) &&
                 (journal.Version is not (2 or 3) || entry.Target.Kind != ObjectAuditKind.RegistryKey)) ||
                (entry.PendingRegistryWrite is { } pending && (pending.Identity != ExpectedIdentity(entry) ||
                    pending.Sacl == null || pending.DesiredSacl == null ||
                    (pending.Sacl != entry.Before && pending.Sacl != entry.After) ||
                    (pending.DesiredSacl != entry.Before && pending.DesiredSacl != entry.After) || pending.Sacl == pending.DesiredSacl)))
                throw new InvalidOperationException("Invalid registry recovery transition or downgraded journal.");
            if (entry.IsSettingsLoad) ValidateSettingsSacl(entry.Before, entry.After, entry.Target.IncludeDescendants);
            else if (entry.After != AddWriteAudit(entry.Before, entry.Target.Kind, entry.Target.IncludeDescendants))
                throw new InvalidOperationException("Object-auditing journal contains an unrecognized SACL transition.");
        }
    }

    private IObjectAuditHandle? OpenOrGap(ObjectAuditTarget target, List<string> gaps)
    {
        try { return _runtime.Open(target); }
        catch (Exception ex) when (IsTargetFailure(ex)) { gaps.Add($"{target.Path}: {ex.Message}"); return null; }
    }

    internal static string AddWriteAudit(string sacl, ObjectAuditKind kind, bool includeDescendants = true)
    {
        var descriptor = new RawSecurityDescriptor(sacl);
        var mask = kind == ObjectAuditKind.RegistryKey ? RegistryWriteMask : FileWriteMask;
        var inheritance = !includeDescendants ? AceFlags.None : kind == ObjectAuditKind.Directory
            ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : kind == ObjectAuditKind.RegistryKey ? AceFlags.ContainerInherit : AceFlags.None;
        var flags = inheritance | AceFlags.SuccessfulAccess | AceFlags.FailedAccess;
        var sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var acl = descriptor.SystemAcl ?? new RawAcl(GenericAcl.AclRevision, 1);
        if (acl.Cast<GenericAce>().OfType<CommonAce>().Any(ace =>
                ace.AceQualifier == AceQualifier.SystemAudit && !ace.IsCallback && ace.SecurityIdentifier == sid &&
                (ace.AceFlags & (flags | AceFlags.InheritOnly | AceFlags.NoPropagateInherit)) == flags &&
                (ace.AccessMask & mask) == mask)) return sacl;
        var index = 0;
        while (index < acl.Count && (acl[index].AceFlags & AceFlags.Inherited) == 0) index++;
        acl.InsertAce(index, new CommonAce(flags, AceQualifier.SystemAudit, mask, sid, false, null));
        descriptor.SystemAcl = acl;
        descriptor.SetFlags(descriptor.ControlFlags | ControlFlags.SystemAclPresent);
        return descriptor.GetSddlForm(AccessControlSections.Audit);
    }

    internal static string NormalizeNativeSacl(RawSecurityDescriptor descriptor)
    {
        // Windows may set automatic-inheritance bookkeeping flags during propagation.
        // Compare actual ACEs and protection, not those derived bookkeeping bits.
        var flags = ControlFlags.SelfRelative | (descriptor.ControlFlags & ControlFlags.SystemAclProtected);
        if (descriptor.SystemAcl != null) flags |= ControlFlags.SystemAclPresent;
        return new RawSecurityDescriptor(flags, null, null, descriptor.SystemAcl, null)
            .GetSddlForm(AccessControlSections.Audit);
    }

    internal static ObjectAuditTarget RootOf(ObjectAuditTarget target) => string.IsNullOrEmpty(target.Root) ? target :
        new(target.Kind == ObjectAuditKind.RegistryKey ? ObjectAuditKind.RegistryKey : ObjectAuditKind.Directory, target.Root)
        { Root = target.Root, RootIdentity = target.RootIdentity, IncludeDescendants = target.IncludeDescendants, RootConfigurationOnly = target.RootConfigurationOnly };

    private static int EntryDepth(ObjectAuditEntry entry) => entry.Target.Path.Count(c => c == '\\');

    private static Dictionary<string, ObjectAuditEntry> EntriesByPath(IEnumerable<ObjectAuditEntry> entries)
    {
        var result = new Dictionary<string, ObjectAuditEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
            if (!result.TryAdd(entry.Target.Path.TrimEnd('\\'), entry))
                throw new InvalidOperationException("Object-auditing plan contains duplicate object paths.");
        return result;
    }

    private static IEnumerable<ObjectAuditEntry> AncestorsOf(
        ObjectAuditEntry entry,
        IReadOnlyDictionary<string, ObjectAuditEntry> entriesByPath)
    {
        var path = entry.Target.Path.TrimEnd('\\');
        while (true)
        {
            var separator = path.LastIndexOf('\\');
            if (separator <= 0) yield break;
            path = path[..separator];
            if (entriesByPath.TryGetValue(path, out var ancestor) && ancestor.Target.Kind != ObjectAuditKind.File)
                yield return ancestor;
        }
    }

    internal static bool HasInheritedWriteAudit(string sacl, ObjectAuditKind kind)
    {
        var mask = kind == ObjectAuditKind.RegistryKey ? RegistryWriteMask : FileWriteMask;
        return new RawSecurityDescriptor(sacl).SystemAcl?.Cast<GenericAce>().OfType<CommonAce>().Any(ace =>
            ace.AceQualifier == AceQualifier.SystemAudit && ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.WorldSid) &&
            (ace.AceFlags & AceFlags.Inherited) != 0 && (ace.AccessMask & mask) == mask) == true;
    }

    internal static bool IsTargetFailure(Exception ex) => ex is IOException or UnauthorizedAccessException or
        InvalidOperationException or System.ComponentModel.Win32Exception or System.Security.SecurityException or
        ArgumentException or CryptographicException;
}

/// <summary>Bounded, atomically replaced, CurrentUser-DPAPI journal under the active session.</summary>
internal sealed class ObjectAuditJournalFile : IObjectAuditJournalStore
{
    internal RegistryAuditIdentityHistoryStore RegistryHistory { get; }
    private const int MaximumBytes = 16 * 1024 * 1024;
    private readonly string _path;
    private readonly byte[] _entropy;
    private readonly MonitoringConfigurationStore _portableStore;
    private readonly string _portableSlot;
    // Reuse the existing native CurrentUser DPAPI primitive with a distinct purpose/scope entropy.
    private readonly IAgentPairingSecretProtector _protector = new CurrentUserDpapiAgentPairingSecretProtector();
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
    };

    internal static string Scope(InvestigationSessionPaths paths) =>
        Path.GetFullPath(paths.SessionRoot).TrimEnd('\\').ToUpperInvariant() + "|" + Environment.MachineName;

    public ObjectAuditJournalFile(InvestigationSessionPaths paths, MonitoringConfigurationStore? portableStore = null)
    {
        _path = Path.Combine(paths.SessionRoot, "agent-windows-security-object-audit.dpapi");
        _portableStore = portableStore ?? new MonitoringConfigurationStore();
        RegistryHistory = new RegistryAuditIdentityHistoryFile(_portableStore);
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes("DFIRoscope.ObjectAudit.v1|" + Scope(paths)));
        _portableSlot = "objects-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Scope(paths))));
    }

    public ObjectAuditJournal? Read()
    {
        WindowsObjectAuditRuntime.ValidateLocalPath(_path, allowFile: true);
        FileStream stream;
        try { stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (FileNotFoundException)
        {
            if (_portableStore.HasBackups(_portableSlot))
                throw new InvalidOperationException("SACL recovery reference is missing while portable originals exist.");
            return null;
        }
        using var ownedStream = stream;
        if (stream.Length <= 0 || stream.Length > MaximumBytes) throw new InvalidOperationException("Invalid object-audit journal size.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        var clear = _protector.Unprotect(bytes, _entropy);
        try
        {
            var journal = JsonSerializer.Deserialize<ObjectAuditJournal>(clear, Options) ?? throw new InvalidOperationException("Empty object-audit journal.");
            if (string.IsNullOrEmpty(journal.PortableBackupId))
            {
                if (journal.Version is 2 or 3 || _portableStore.HasBackups(_portableSlot))
                    throw new InvalidOperationException("SACL recovery reference lost its protected backup identity.");
                return journal;
            }
            if (!Guid.TryParseExact(journal.PortableBackupId, "N", out _))
                throw new InvalidOperationException("Invalid SACL backup identity.");
            var portable = _portableStore.Read<PortableObjectAuditBackup>(_portableSlot + "-" + journal.PortableBackupId)
                ?? throw new InvalidOperationException("Required portable SACL backup is missing; restoration withheld.");
            if (portable.EncryptedJournal == null || portable.EncryptedJournal.Length is <= 0 or > MaximumBytes)
                throw new InvalidOperationException("Invalid portable SACL baseline size.");
            if (!portable.EncryptedJournal.SequenceEqual(bytes))
            {
                if (journal.Version is not (2 or 3))
                    throw new InvalidOperationException("Portable SACL backup and session journal differ; restoration withheld.");
                var original = _protector.Unprotect(portable.EncryptedJournal, _entropy);
                try
                {
                    var anchor = JsonSerializer.Deserialize<ObjectAuditJournal>(original, Options);
                    if (anchor == null || anchor.PortableBackupId != journal.PortableBackupId || !SameBaseline(anchor, journal))
                        throw new InvalidOperationException("Portable SACL originals and current journal differ; restoration withheld.");
                }
                finally { CryptographicOperations.ZeroMemory(original); }
            }
            return journal;
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    public void Write(ObjectAuditJournal journal)
    {
        WindowsObjectAuditRuntime.ValidateLocalPath(_path, allowFile: true);
        // Validate the existing pair before reusing its immutable originals. The session journal
        // alone owns pending/current progress; portable data never reconstructs that authority.
        var prior = Read();
        var reuseAnchor = journal.Version is 2 or 3 && prior?.Version == journal.Version &&
            prior.PortableBackupId.Length > 0 && SameBaseline(prior, journal);
        var backupId = reuseAnchor ? prior!.PortableBackupId : Guid.NewGuid().ToString("N");
        var clear = JsonSerializer.SerializeToUtf8Bytes(journal with { PortableBackupId = backupId }, Options);
        byte[] encrypted;
        try { encrypted = _protector.Protect(clear, _entropy); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        if (encrypted.Length > MaximumBytes) throw new InvalidOperationException("Object-audit journal exceeds its size limit.");
        if (!reuseAnchor) _portableStore.WriteOnce(_portableSlot + "-" + backupId, new PortableObjectAuditBackup(encrypted));
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(encrypted);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, _path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static bool SameBaseline(ObjectAuditJournal left, ObjectAuditJournal right)
    {
        if (left.Version is not (2 or 3) || right.Version != left.Version || left.Scope != right.Scope ||
            left.Entries == null || right.Entries == null || left.Entries.Length != right.Entries.Length) return false;
        // Record equality includes every target and original field. Only these explicitly mutable
        // fields are excluded; future immutable fields automatically join the equality contract.
        return left.Entries.Zip(right.Entries).All(pair => pair.First != null && pair.Second != null &&
            pair.First with { CurrentIdentity = "", PendingRegistryWrite = null } ==
            pair.Second with { CurrentIdentity = "", PendingRegistryWrite = null });
    }

    private sealed record PortableObjectAuditBackup(byte[] EncryptedJournal);
}
