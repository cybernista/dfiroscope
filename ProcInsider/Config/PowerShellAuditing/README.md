# DFIRoscope Live PowerShell Auditing Profile

This profile is read-only metadata for the agent-owned host-monitoring workflow. The viewer may
inspect current policy state and open this description, but it does not write HKLM policy or create
the transcript directory.

Select PowerShell auditing options through **Configure Host Monitoring**. The connected elevated
local agent captures the original state, applies only the confirmed settings, records per-area
results under the active session, and restores the recorded baseline through **Revert to original
config** where safe.
