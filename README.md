# DFIRoscope Live

DFIRoscope Live is a Windows investigation and cybersecurity learning application. This source archive contains the complete product tree used to build the corresponding official Viewer and local Agent binaries.

This is DFIRoscope Live 0.4.0, adding AI Assistance, Application Comparison, Network, Persistence, and filesystem artifacts to Processes and the combined Windows event workspace. Releases use semantic version numbers; earlier EDU releases retain their historical identities.

This edition publishes exactly these feature groups:

- `process-listing`
- `selected-process-details`, which depends on `process-listing`
- `investigation-workspaces`, which depends on `process-listing` and `selected-process-details`
- `events-workspace`, which depends on `investigation-workspaces`; Windows Security and aggregate event families publish into it independently
- `agents-capture`
- `event-telemetry`, which presents Runtime, ETW, PowerShell, Other Windows, and Sysmon evidence and owns capture for the four non-Runtime families
- `security-monitoring-configuration`, which depends on `agents-capture` and owns supported non-Security host-monitoring checks, configuration, and reversal
- `windows-security-events`, whose live capture depends on `agents-capture`
- `ai-assistance`, which depends on `selected-process-details` and `application-comparison`
- `application-comparison`, which depends on `selected-process-details`
- `network-workspace`, which depends on `investigation-workspaces` and `event-telemetry`
- `persistence`, which depends on `agents-capture`
- `filesystem-artifacts`

`PUBLIC-EDITION.json` is the machine-readable official publication scope. `SOURCE-PROVENANCE.json` binds every supplied file to the private origin commit, one committed disclosure-policy identity/digest, and one deterministic exported-tree digest. The disclosure digest identifies the approved collection scope without supplying any excluded-path inventory. See [BUILD.md](BUILD.md) for the clean build commands.

## Investigation workspaces

Open a capture, then use Explorer to open Processes and Events investigations. Open another instance to compare independent filters, selections and Details; pin an instance to protect it from navigation reuse. The capture-wide Events workspace offers publication-filtered ETW, Security, PowerShell, Other Windows, and Sysmon evidence plus Identity, Provider, Channel and Event ID pivots, with native payload in Data. Runtime remains available in focused selected-process/source views but is excluded from the capture-wide pivots. Missing or ambiguous identities remain visible. Coverage may be Unknown; a displayed event total does not assert complete acquisition. Workspace tabs are transient and are not restored after closing the application.

## Local analyst workflows

This edition supports the standalone local Viewer and Agent workflow. Use AI Assistance with your own configured provider and explicit analyst consent before cloud calls; the package includes no provider credentials. Provider configuration and its protected credential vault stay application-local, while interaction permission stays session-scoped.

Use Application Comparison to inspect the selected application's captured state. Network and Persistence views depend on available captured sources and the saved collection policy; unavailable or partial sources do not establish absence. Explicitly request Agent live Prefetch analysis, then browse the saved parsed results in Artifacts. This live workflow does not retain original `.pf` files or add an offline evidence store.

Infrastructure deployment and source-authoring workflows are outside this edition's supported scope.

## Development status

DFIRoscope is under active development. This archive is the complete disclosed graph used for the corresponding official binaries; it makes no availability, review, documentation, support, or functional claim beyond the groups in `PUBLIC-EDITION.json`.

Modified builds are unofficial and unsupported. Official availability is defined by `PUBLIC-EDITION.json`, the release tag and notes, the shipped binaries, and the corresponding release documentation.

## License and branding

Original source code and documentation are licensed under the [Apache License, Version 2.0](LICENSE), including commercial use, modification, and redistribution under its terms. Release version numbers do not change the license terms.

Future releases may use different terms; Apache-2.0 rights already granted for this snapshot are not revoked by a later license change.

DFIRoscope names and logos are reserved as trademarks separately from the software license; see [TRADEMARKS.md](TRADEMARKS.md) and [NOTICE](NOTICE). No trademark registration is claimed. Dependencies retain their own terms; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), `licenses/components.json`, and the referenced license texts under `licenses/`.
