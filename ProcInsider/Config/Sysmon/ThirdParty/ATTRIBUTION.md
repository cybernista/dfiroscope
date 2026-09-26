# Third-party Sysmon profiles

These XML files are unmodified copies. Their selection in DFIRoscope does not imply
endorsement by the upstream authors. Applying any selection replaces the currently
active Sysmon rules. Review local compatibility, event volume and disk use first.

| Packaged file | Upstream source | Pinned revision or release | License | SHA-256 |
| --- | --- | --- | --- | --- |
| `SwiftOnSecurity.Sysmon.xml` | [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config/blob/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml) | `1836897f12fbd6a0a473665ef6abc34a6b497e31` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), as stated in the XML header | `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162` |
| `olafhartong.Balanced.xml` | [sysmon-modular release](https://github.com/olafhartong/sysmon-modular/releases/tag/configs-082cba578667) | `configs-082cba578667`, Sysmon 15.21 asset `sysmonconfig.xml` | [MIT](license.md) | `F115AAC5770DAE468E5CFB48C58A8B6E37588208A31F1B746812C534577A244B` |
| `olafhartong.BalancedWithFileDelete.xml` | Same release | `configs-082cba578667`, Sysmon 15.21 asset `sysmonconfig-with-filedelete.xml` | [MIT](license.md) | `92B1239486C0EA8AB4B71EC0298AE89D5E814751337CEF0B25B3E3ECCF96C050` |
| `olafhartong.ExcludesOnly.xml` | Same release | `configs-082cba578667`, Sysmon 15.21 asset `sysmonconfig-excludes-only.xml` | [MIT](license.md) | `BAE0A6B67FFAA1A92683F663043B66F22CFB9CE74E3496838D2EA992BAF00ECE` |

The SwiftOnSecurity file retains its original attribution comments. The
[NextronSystems fork](https://github.com/NextronSystems/sysmon-config) is not
bundled: its XML credits the CC BY source but does not declare redistribution
terms for its additional contributions. Analysts can review it upstream.

The Olaf Hartong **Balanced with FileDelete** profile archives deleted files and
can grow disk usage. **Excludes only** is highly verbose. The release describes
these three assets as generated for Sysmon 15.21; test their application against
the installed Sysmon version before relying on them.
