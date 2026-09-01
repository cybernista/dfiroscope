# DFIRoscope Live

DFIRoscope Live is a Windows investigation and cybersecurity learning application. This source archive contains the complete product tree used to build the corresponding official Viewer and local Agent binaries.

The S1E1 official binaries publish exactly these feature groups:

- `process-listing`
- `selected-process-details`, which depends on `process-listing`
- `agents-capture`

`PUBLIC-EDITION.json` is the machine-readable official publication scope. `SOURCE-PROVENANCE.json` binds every supplied file to the private origin commit, one committed disclosure-policy identity/digest, and one deterministic exported-tree digest. The disclosure digest identifies the approved collection scope without supplying any excluded-path inventory. See [BUILD.md](BUILD.md) for the clean build commands.

## Development status

DFIRoscope is under active development. This archive is the complete disclosed graph used for the corresponding official binaries; it makes no availability, review, documentation, support, or functional claim beyond the groups in `PUBLIC-EDITION.json`.

Modified builds are unofficial and unsupported. Official availability is defined by `PUBLIC-EDITION.json`, the release tag and notes, the shipped binaries, and the corresponding EDU training.

## License and branding

Original source code and documentation are licensed under the [Apache License, Version 2.0](LICENSE), including commercial use, modification, and redistribution under its terms. The educational label describes available features, not a noncommercial restriction.

Future releases may use different terms; Apache-2.0 rights already granted for this snapshot are not revoked by a later license change.

DFIRoscope names and logos are reserved as trademarks separately from the software license; see [TRADEMARKS.md](TRADEMARKS.md) and [NOTICE](NOTICE). No trademark registration is claimed. Dependencies retain their own terms; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), `licenses/components.json`, and the referenced license texts under `licenses/`.
