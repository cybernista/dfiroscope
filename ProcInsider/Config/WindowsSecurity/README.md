# Windows Security collection configuration

This extends the existing monitoring profile; it does not introduce policy tiers.
It contains 35 audit subcategories. Filtering Platform
Connection and Removable Storage now enable success and failure alongside the
existing process creation/termination, PnP, File System and Registry settings.
WFP and removable-storage auditing can generate substantial Security log volume;
review log capacity, retention and capture throughput before deployment.

## Explicit object auditing

The shared Agent monitoring form has two additional choices, both off by default:

- Audit user Desktop, Documents and Downloads writes, including Public equivalents.
- Audit writes to selected persistence and security registry keys.

Both require **Configure audit policy**. Save, startup and capture start do not
deploy SACLs. **Check Monitoring** is read-only; **Configure Monitoring** explicitly
deploys through the authorized elevated Agent. A SACL controls auditing, not access
permission: deployment never grants access, takes ownership or changes the DACL.

Folder discovery inventories local account profiles and reads each loaded user's
`User Shell Folders` in HKU, not the Agent's HKCU. Supported local redirection and
OneDrive variables come from that user. Unloaded hives, missing keys/folders,
unresolved variables, UNC/device paths and reparse roots/ancestors are reported
as gaps, not created or loaded. Recheck and explicitly deploy after previously
unavailable users sign in. Whole volumes, whole-profile redirection, Windows,
Program Files, ProgramData and AppData are not selected. There is no automatic
new-profile watcher and no claim of complete coverage for offline profiles.

Registry roots are existing 64-bit-view keys (plus the explicitly listed 32-bit
Run locations):

- HKLM `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, and the
  corresponding `SOFTWARE\WOW6432Node` paths.
- HKLM `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` and
  `Image File Execution Options`.
- HKLM `SOFTWARE\Policies\Microsoft\Windows Defender`.
- HKLM `SYSTEM\ControlSetNNN\Services`, resolving the active control set at check/deploy.
- Each loaded account's HKU `Software\Microsoft\Windows\CurrentVersion\Run`,
  `RunOnce`, `Policies\Explorer\Run`, and
  `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`.

HKLM `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` is audited for
writes to that security-policy key itself. Its audit entry is deliberately
non-inheriting and the `Audit` child subtree is excluded because the Agent's
separate command-line policy configuration can update or create that child.
This preserves coverage of direct security-policy values without giving two
recovery owners authority over the same object. The excluded child remains a
reported coverage gap even when the command-line choice is currently off. An
older active SACL baseline covering that child blocks command-line changes until
its recovery is resolved.

Folder audit entries cover write/create/append, extended attributes, attributes,
delete/delete-child, DACL and ownership changes. Registry entries cover set-value,
create-subkey, delete, DACL and ownership changes. Both audit success and failure
for Everyone, normally with inheritance; the Windows security-policy root above
is the explicit non-inheriting exception. Ordinary reads/listing are excluded. Existing
rules and inheritance protection are preserved. New operations back up, configure
and verify only the selected roots. Windows `SetSecurityInfo` propagates inheritable
entries normally; the application does not enumerate or individually write children.
Disabled child inheritance is respected. Descendant coverage is not individually
verified and no replace-all-child-rules operation is used. Root access failures are
reported individually; other backed-up roots can proceed. No additional backup,
share or application-data directory is silently selected.

## Recovery and reporting

New root settings use snapshot/manifest version 2 and protected journal version 3.
The existing Save and Restore forms and flow are unchanged. Root settings can be
saved inside an audited folder because child inventory is no longer part of the
backup. Restore loads the saved root SACLs and lets Windows update inherited entries;
it does not promise an exact historical snapshot of descendants after external edits.
Root identity, protection, durable original-state and immutable portable-anchor checks
remain enforced. Nonempty legacy journals must be restored before new root Apply.
New registry root settings bind to the independently selected canonical key path:
ordinary value/subkey changes do not invalidate Restore, and a deleted/recreated key
at that path can receive the saved audit settings. Legacy per-object recovery keeps
its strict last-write identity. Explicit root registry Restore may replace the current
root audit rules with the selected saved rules; desired-descriptor, inheritance/protection
and post-write checks still apply. Ordinary Apply and Check retain current-SACL drift checks.

### Legacy per-object recovery

The following compatibility behavior remains for snapshot version 1 and journal
versions 1/2. These records are never reinterpreted as root-mode operations.

Before any selected Windows mutation, the Agent atomically saves the parent
original-state record and an empty recovery journal. When command-line policy
and registry auditing are combined, it applies or confirms that child value
before discovering the object tree; this prevents the authorized child-key
creation from invalidating its parent identity. Any required command-line
registry write is preceded by a durable
`processCommandLineMutationMayHaveOccurred` marker. The Agent clears it only
when the success result is atomically persisted; restart reversal treats a
surviving marker as an applied mutation and clears it only after exact restore.
It writes only when the current value still matches the intended DWORD `1`,
clears an already-restored baseline without writing, and retains any third
state as explicit drift for later review.
Before the first object write,
the Agent then saves the complete bounded plan (including unchanged nodes),
original/intended SACLs and object identities in the session-owned, CurrentUser-DPAPI-protected
`agent-windows-security-object-audit.dpapi`. Repeated deployment preserves the
original baseline. Deployment writes descendants before their inheritance-source
ancestors; restoration removes those ancestor sources before restoring descendants.
This keeps each journaled SACL transition stable while Windows resolves inheritance.
A failed descendant withholds its pending ancestor source; an already-active or
unverified managed ancestor blocks a pending descendant before mutation. These
checks use the complete retained journal even when `Prepare` omits a drifted or
unreadable ancestor or descendant from the new plan. A readable-again omitted
descendant still at its pending baseline withholds ancestor activation without
being silently added back to the mutation plan. During
recovery, a failed ancestor similarly withholds its descendants. All such dependency
gaps retain the complete journal for a later safe retry.
The parent Windows Security original-state record is also
written by atomic replacement and records the expected journal. An existing
journal with a missing, malformed or incompatible parent record blocks Check,
deployment and baseline recapture; the Agent never treats that recovery state as
a fresh deployment or replaces the first audit-policy/command-line baseline.
Compatibility includes the exact Agent identity, case-insensitive host identity,
Windows Security scope and a consistent completion state. A completed recovery
may create a fresh baseline only after its validated journal is empty; that new
baseline retains the empty-journal relationship.
Deployment verifies the resulting SACL and reports individual
gaps in the existing monitoring result and operational log; it does not write
new evidence directly. Keep the session and run recovery as the same account.

**Revert to original config** restores journaled objects only when both identity
and current SACL match the recorded transition. A changed/replaced object or
unreadable journal stops that restoration; its baseline is retained for review,
and audit-policy restoration is withheld on object-restoration conflicts.
The whole journal is retained after partial recovery, including when the known
objects have already been restored. A new, unjournaled file descendant with inherited
auditing, or registry descendant containing audit entries, requires manual review: a matching ACE does not establish that this
deployment owns it. Objects moved outside the selected roots cannot be discovered
reliably and are not automatically modified. Registry identity conservatively
includes canonical name and last-write time. Agent writes may change that time:
journal version 2 retains the immutable original identity and records pending and
verified current identities separately. Verification uses the same open key handle;
the bound root is rechecked against its own verified journal identity. An interrupted
write without durable verification, an outside change, or a version-1 identity mismatch
requires manual review; matching SACL content alone cannot recover the identity.
Registry handles do not lock
out concurrent administrator changes. Recovery is explicit, including after a crash;
it is not a background service or automatic rollback. Unchecking a choice does
not remove already deployed entries: use Revert. A failed audit-policy restore
remains retryable after object recovery has finished. The existing auditpol baseline
restoration remains a full policy restore, not an audit-policy drift merge.

Older same-computer registry exports can be reused only through a continuous chain
of verified Agent identity transitions. That bounded history is separately protected
with current-user DPAPI, serialized across Agent processes, and limited to 256 prior
identities per key and 8,192 keys. Outside drift invalidates old aliases. Missing,
malformed or full history never authorizes an identity match. If history cannot be
updated during exact journal-based restoration, recovery can finish with a visible
compatibility warning: older exports may no longer load. The protected recovery
journal and identity/SACL checks remain mandatory. Keep `settings/SecurityConfig`
with the portable executable and retain the original session for recovery.

Each version-2 journal references an immutable protected portable baseline. Its
original fields must match that exact backup, while the session journal alone
tracks pending writes and verified current identities. Progress updates reuse the
baseline rather than retaining a full backup for every key write. A changed baseline
gets a new backup; old originals remain after successful recovery. Full-journal
encryption and durable writes still grow with object count and transition count.
Registry snapshots use stored native SACL values: the Win32 security reader can
otherwise synthesize inherited flags. Older journals that differ from native state
are not silently converted; their recovery remains blocked for review.
Windows can represent a restored absent SACL as a present null SACL. Verification
preserves no-auditing semantics, audit entries and protection, with owner/group/DACL
checked separately; it does not promise identical descriptor bytes or presence bits.

## Collection limits

This change configures Security EVTX generation only; it adds no detector,
blocking, other event channel or collector/normalizer refactor. Existing process
command lines remain the source for command-line shadow-copy tools. Security
alone does not provide general DNS query logging or universal API-call tracing.

4656 records requested access, 4663 records access-right use (DELETE can also
accompany rename), and 4660 records deletion but requires correlation for the
object path. 4657 concerns registry value changes. 6416 is external-device
recognition; Removable Storage auditing is a separate policy with no per-object
SACL requirement and can include read activity. WFP allow/block events describe
filtering decisions, not proof that network traffic completed. Process creation
events provide parent/child context within existing correlation limitations.

The handle-bound [NtSetSecurityObject API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject)
is used with SACL information only. Native fixture validation must prove
non-recursive writes and preservation/restoration on the supported Windows host.
