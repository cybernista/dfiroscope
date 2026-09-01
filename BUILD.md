# Build DFIRoscope Live

## Requirements

- Windows 10 or Windows 11, x64
- the stable .NET SDK selected by `global.json` (the .NET 10.0.3xx feature band)

## Restore and build

From the source root:

```powershell
dotnet --version
dotnet restore DFIRoscope.Public.slnx --locked-mode
dotnet build DFIRoscope.Public.slnx --configuration Release --no-restore --warnaserror
```

`DFIRoscope.Public.slnx` contains the production Viewer, local Agent, Core, and Windows Infrastructure projects. It intentionally excludes private developer tooling and campaign workflow material.

## Framework-dependent publish

This form requires the .NET 10 Desktop Runtime on the target computer.

```powershell
dotnet publish ProcInsider/ProcInsider.csproj --configuration Release --no-restore --self-contained false --property:PublishDir=artifacts/framework-dependent/Viewer/
dotnet publish ProcInsider.Agent/ProcInsider.Agent.csproj --configuration Release --no-restore --self-contained false --property:PublishDir=artifacts/framework-dependent/Agent/
```

## Self-contained Windows x64 publish

This form carries the required .NET runtime.

```powershell
dotnet publish ProcInsider/ProcInsider.csproj --configuration Release --no-restore --runtime win-x64 --self-contained true --property:PublishDir=artifacts/self-contained-win-x64/Viewer/
dotnet publish ProcInsider.Agent/ProcInsider.Agent.csproj --configuration Release --no-restore --runtime win-x64 --self-contained true --property:PublishDir=artifacts/self-contained-win-x64/Agent/
```

Keep Viewer and Agent in separate directories. The official release pipeline accepts only this provenance-bound disclosed graph, runs these production publishes from a disposable exact copy, and then adds bounded compatibility aliases, signing disclosure, checksums, and release provenance. An official build binding must retain the same disclosure-policy identity/digest and exported-tree digest as `SOURCE-PROVENANCE.json`.

The disclosed graph makes no product claim beyond `PUBLIC-EDITION.json`. Changing the publication catalog or source produces an unofficial, unsupported build even when compilation succeeds.
