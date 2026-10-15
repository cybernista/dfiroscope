using System.Diagnostics;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

public sealed record StartupNativeObject(string Name, string Path, string Kind, uint Attributes,
    string? ShortcutTarget = null, string? Arguments = null, string? WorkingDirectory = null, bool ShortcutKnown = false);
public sealed record StartupNativeFolder(string DeclarationId, string? Root, string UserSid, string ProfileScope,
    PersistenceCollectionStatus Status, IReadOnlyList<StartupNativeObject> Objects,
    IReadOnlyDictionary<string, PersistenceNativeValue> Declaration, string Diagnostic, bool Attempted = true);
public interface IStartupFoldersNativeReader { IReadOnlyList<StartupNativeFolder> Read(CancellationToken token); }

public sealed class StartupFoldersCollector(EvidenceIdentity identity, IStartupFoldersNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.startup-folders.v1";
    public string CollectorId => Id;
    private readonly IStartupFoldersNativeReader _reader = reader ?? new StartupFoldersNativeReader();
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requestedIdentity, CancellationToken token)
    {
        if (requestedIdentity != identity) throw new InvalidDataException("Startup collector scope mismatch.");
        token.ThrowIfCancellationRequested(); var watch = Stopwatch.StartNew();
        IReadOnlyList<StartupNativeFolder> folders;
        try { folders = _reader.Read(token); }
        catch (Exception ex) when (ServicesDriversNativeReader.ExpectedFailure(ex))
        { folders = [new("StartupDeclarations", null, "", "LocalConfiguredStartup", PersistenceCollectionStatus.Failed, [], new Dictionary<string, PersistenceNativeValue>(), "Startup declarations unavailable; no removals inferred.")]; }
        var incomplete = folders.Any(folder => folder.Attempted && folder.Status != PersistenceCollectionStatus.Complete);
        var results = new List<PersistenceCollectorResult>();
        foreach (var folder in folders)
        {
            token.ThrowIfCancellationRequested();
            var status = !folder.Attempted ? folder.Status : incomplete ? folder.Objects.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial : PersistenceCollectionStatus.Complete;
            var coverage = new PersistenceCoverage(folder.Root?.ToUpperInvariant() ?? folder.DeclarationId, folder.UserSid, "", folder.ProfileScope,
                status == PersistenceCollectionStatus.Complete ? PersistenceSourceAvailability.Available : PersistenceSourceAvailability.Unavailable);
            var artifacts = folder.Objects.Select(entry =>
            {
                var configuration = new Dictionary<string, PersistenceNativeValue>(folder.Declaration, StringComparer.Ordinal)
                {
                    ["ObjectKind"] = Native("FileSystemObjectType", entry.Kind), ["RelevantAttributes"] = Native("FILE_ATTRIBUTE_READONLY_HIDDEN_SYSTEM_DIRECTORY_FLAGS", entry.Attributes & 0x17)
                };
                if (entry.Kind == "Shortcut")
                {
                    configuration["ShortcutTarget"] = Native("ShellLinkRawPath", entry.ShortcutTarget, entry.ShortcutKnown);
                    configuration["ShortcutArguments"] = Native("ShellLinkArguments", entry.Arguments, entry.ShortcutKnown);
                    configuration["ShortcutWorkingDirectory"] = Native("ShellLinkWorkingDirectory", entry.WorkingDirectory, entry.ShortcutKnown);
                }
                return new PersistenceArtifact { EvidenceIdentity = identity, CollectorId = Id, Category = "Startup", Coverage = coverage,
                    NativeName = entry.Name, NativeLocation = entry.Path, Target = entry.ShortcutTarget, Command = entry.ShortcutTarget,
                    Arguments = entry.Arguments, Principal = folder.UserSid.Length == 0 ? "Machine/common" : folder.UserSid, Configuration = configuration };
            }).ToArray();
            if (status == PersistenceCollectionStatus.Complete)
                try { _ = PersistenceComparisonPolicy.Inventory(artifacts); }
                catch (InvalidDataException) { incomplete = true; }
            results.Add(new(Id, coverage, status, artifacts, watch.Elapsed, folder.Diagnostic + (incomplete ? " Startup attempted family incomplete; no folder reconciled or removals inferred." : "")));
        }
        if (incomplete)
            for (var index = 0; index < results.Count; index++)
            {
                if (!folders[index].Attempted) continue;
                var result = results[index]; var coverage = result.Coverage with { SourceAvailability = PersistenceSourceAvailability.Unavailable };
                results[index] = result with { Status = result.Artifacts.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial,
                    Coverage = coverage, Artifacts = result.Artifacts.Select(artifact => artifact with { Coverage = coverage }).ToArray(),
                    DiagnosticSummary = folders[index].Diagnostic + " Startup attempted family incomplete, including conflicting locations; no folder reconciled or removals inferred." };
            }
        return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>(results);
    }
    private static PersistenceNativeValue Native(string type, object? value, bool known = true) => new(type, known ? PersistenceValueState.Known : PersistenceValueState.Unknown, JsonSerializer.Serialize(value));
}
