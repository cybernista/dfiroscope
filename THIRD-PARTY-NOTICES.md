# Third-party notices

DFIRoscope's Apache-2.0 license applies to its original material, not as a replacement for third-party licenses. Preserve the applicable upstream license and attribution notices when redistributing components. This inventory covers all packages in the repository's committed NuGet lock files, including transitive and development dependencies; a particular release may contain only a subset.

The exact package versions, NuGet copyright statements, upstream references, and notice-file mapping are recorded in [licenses/components.json](licenses/components.json). The full license and notice texts are included locally; links to upstream projects are provenance, not substitutes for those texts.

## NuGet components

| Component | Version | License / full text |
|---|---|---|
| CommunityToolkit.Mvvm | 8.4.0 | [MIT](licenses/MIT-CommunityToolkit.txt) |
| Microsoft.Data.Sqlite; Microsoft.Data.Sqlite.Core | 10.0.0 | [MIT](licenses/MIT-dotnet.txt) |
| Microsoft.Diagnostics.NETCore.Client | 0.2.510501 | [MIT](licenses/MIT-dotnet.txt) |
| Microsoft.Diagnostics.Tracing.TraceEvent | 3.2.3 | [MIT](licenses/MIT-TraceEvent.txt) |
| Microsoft.Extensions.DependencyInjection; Microsoft.Extensions.Logging; Microsoft.Extensions.Options; Microsoft.Extensions.Primitives | 6.0.0 | [MIT](licenses/MIT-dotnet.txt) |
| Microsoft.Extensions.DependencyInjection.Abstractions; Microsoft.Extensions.Logging.Abstractions | 10.0.0 | [MIT](licenses/MIT-dotnet.txt) |
| Npgsql | 10.0.3 | [PostgreSQL](licenses/PostgreSQL-Npgsql.txt) |
| SQLitePCLRaw.bundle_e_sqlite3; SQLitePCLRaw.config.e_sqlite3; SQLitePCLRaw.core; SQLitePCLRaw.provider.e_sqlite3 | 3.0.3 | [Apache-2.0](licenses/Apache-2.0-SQLitePCLRaw.txt) |
| SourceGear.sqlite3 (native SQLite) | 3.53.4 | [Public domain declaration](licenses/Public-Domain-SQLite.txt) |
| System.CodeDom; System.Management | 9.0.0 | [MIT](licenses/MIT-dotnet.txt) |
| System.Diagnostics.EventLog | 10.0.0 | [MIT](licenses/MIT-dotnet.txt) |
| System.Reflection.TypeExtensions | 4.7.0 | [MIT](licenses/MIT-dotnet.txt) |

Microsoft packages carry `© Microsoft Corporation. All rights reserved.` in their NuGet metadata; their upstream MIT text also credits the .NET Foundation and Contributors. CommunityToolkit credits the .NET Foundation and Contributors. Npgsql's license credits `Copyright (c) 2002-2025, Npgsql`, and its package metadata credits the Npgsql Development Team. SQLitePCLRaw credits SourceGear, LLC (2014-2025 or 2014-2026 depending on the package); the exact statements are preserved in the inventory.

### Upstream notices within packages

These upstream files are retained in full, including their original scope descriptions. They can mention parts of an upstream project not present in a particular DFIRoscope package; their inclusion does not claim that every listed component is shipped.

- [CommunityToolkit notices](licenses/ThirdPartyNotices-CommunityToolkit.txt)
- [.NET 6 package notices](licenses/ThirdPartyNotices-dotnet-6.txt)
- [.NET 9 package notices](licenses/ThirdPartyNotices-dotnet-9.txt)
- [.NET 10 package notices](licenses/ThirdPartyNotices-dotnet-10.txt)
- [System.Reflection.TypeExtensions 4.7.0 package notices](licenses/ThirdPartyNotices-dotnet-core-3.txt)

### Native and interop files

TraceEvent's [3.2.3 NuGet distribution](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.3) declares MIT and supplies `Microsoft.Diagnostics.FastSerialization.dll`, `Dia2Lib.dll`, `TraceReloggerLib.dll`, and architecture-specific `KernelTraceControl.dll`, `KernelTraceControl.Win61.dll`, and `msdia140.dll`. Applicable files are copied by the upstream package's build assets. The TraceEvent attribution and MIT text accompany these package assets; DFIRoscope does not relicense them or claim authorship or availability of their native source code.

`SourceGear.sqlite3` supplies the native SQLite library used through SQLitePCLRaw. Its package metadata credits SourceGear while its included license file declares SQLite public domain. See [SQLite's upstream copyright explanation](https://sqlite.org/copyright.html).

## .NET runtime

Framework-dependent packages require a separately installed compatible Microsoft .NET Desktop Runtime. Self-contained Standalone packages include the runtime and retain its own `licenses/dotnet/LICENSE.txt` and `licenses/dotnet/ThirdPartyNotices.txt` at the archive root, copied by the release build. These are additional to the NuGet notices above; do not remove them from self-contained distributions.

## Optional tools and content

- **YARA-X 1.19.0:** the repository pins an optional, separately acquired scanner. It is not added to ordinary releases by this licensing change. The [BSD-3-Clause license](licenses/BSD-3-Clause-YARA-X.txt) credits `Copyright (c) 2024. The YARA-X Authors. All Rights Reserved.` Any future bundle must also audit and preserve the notices applicable to that exact binary and its dependencies.
- **Zeek, Volatility, Sysmon, and Process Monitor:** integrations use separately supplied tools. Those tools are not relicensed by DFIRoscope and must be obtained and used under their respective terms. In particular, Microsoft Sysinternals tools have their own license terms; do not describe them as Apache-licensed DFIRoscope components.
- **Imported Sigma/YARA rules, databases, and investigation content:** user-supplied material retains its own rights and terms. Importing it does not grant redistribution rights.

## Maintenance

When changing dependencies, review both direct and transitive packages, native assets, and embedded notices. Update the versioned inventory and full texts together. The repository licensing validator checks lock-file coverage and payload completeness; it is not a legal opinion or an automated determination of license compatibility. A new binary bundle requires a fresh review, not merely a package-name entry here.
