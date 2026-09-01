# DFIRoscope Live Security Monitoring Profile

This profile describes an intentionally noisy malware-triage monitoring baseline. It may capture
sensitive command lines, PowerShell content, transcripts, file activity, and registry activity.
Do not silently deploy it to ordinary production workstations.

The viewer treats this directory as read-only profile metadata. It does not launch scripts, request
elevation, create machine-wide paths, clear event logs, export audit policy, or apply/remove policy.

Supported host changes use the connected elevated local agent:

- **Check Host Monitoring** performs read-only prerequisite and status checks.
- **Configure Host Monitoring** saves explicit selected actions and deploys them through the typed
  agent command after confirmation.
- **Revert to original config** restores the pre-deployment state where the agent recorded a safe
  reversal and reports unsupported or partial areas instead of guessing.

The agent consumes `auditpol/monitoring-audit-policy.json` as non-executable policy data and
`config/event-logs.json` as event-log configuration data. Deployment results and reversal state are
recorded under the active `SessionPathService` session. The profile intentionally has no executable
`actions` entries or standalone install/verify/remove/clear helper package.
