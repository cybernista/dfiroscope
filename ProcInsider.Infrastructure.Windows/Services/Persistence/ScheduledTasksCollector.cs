using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

public sealed record ScheduledTaskNativeEntry(string Path, string Xml);
public sealed record ScheduledTasksNativeSnapshot(PersistenceCollectionStatus Status, IReadOnlyList<ScheduledTaskNativeEntry> Tasks, string Diagnostic);
public interface IScheduledTasksNativeReader
{
    ScheduledTasksNativeSnapshot Read(CancellationToken cancellationToken);
}

public sealed class ScheduledTasksCollector(EvidenceIdentity identity, IScheduledTasksNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.scheduled-tasks.v2";
    public string CollectorId => Id;
    private readonly IScheduledTasksNativeReader _reader = reader ?? new ScheduledTasksNativeReader();
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requestedIdentity, CancellationToken cancellationToken)
    {
        if (requestedIdentity != identity) throw new InvalidDataException("Task collector scope mismatch.");
        cancellationToken.ThrowIfCancellationRequested();
        var watch = Stopwatch.StartNew();
        ScheduledTasksNativeSnapshot snapshot;
        try { snapshot = _reader.Read(cancellationToken); }
        catch (Exception ex) when (ScheduledTasksNativeReader.IsExpectedNativeFailure(ex))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var unavailable = new PersistenceCoverage("LocalTasks", "", "", "RecursiveIncludingAuthorizedHidden", PersistenceSourceAvailability.Unavailable);
            return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>([new(Id, unavailable, PersistenceCollectionStatus.Failed, [], watch.Elapsed, "Task Scheduler native source unavailable; no removals inferred.")]);
        }
        var coverage = new PersistenceCoverage("LocalTasks", "", "", "RecursiveIncludingAuthorizedHidden", snapshot.Status == PersistenceCollectionStatus.Complete ? PersistenceSourceAvailability.Available : PersistenceSourceAvailability.Unavailable);
        var artifacts = new List<PersistenceArtifact>();
        var status = snapshot.Status;
        foreach (var task in snapshot.Tasks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var xmlReader = XmlReader.Create(new StringReader(task.Xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = ScheduledTasksNativeReader.MaxXmlCharacters });
                var xml = XDocument.Load(xmlReader);
                var root = xml.Root ?? throw new InvalidDataException("Missing task root.");
                if (root.Descendants().Any(element => element.Ancestors().Take(65).Count() > 64)) throw new InvalidDataException("Task XML nesting bound reached.");
                if (root.Name.LocalName != "Task" || root.Name.NamespaceName != "http://schemas.microsoft.com/windows/2004/02/mit/task" || !task.Path.StartsWith('\\')) throw new InvalidDataException("Invalid native task identity/schema.");
                var ns = root.Name.Namespace;
                var actions = root.Element(ns + "Actions")?.Elements().ToArray() ?? [];
                if (actions.Length == 0 || actions.Any(action => action.Name.Namespace != ns || action.Name.LocalName switch
                    {
                        "Exec" => string.IsNullOrWhiteSpace(action.Element(ns + "Command")?.Value),
                        "ComHandler" => !Guid.TryParse(action.Element(ns + "ClassId")?.Value, out _),
                        "SendEmail" => string.IsNullOrWhiteSpace(action.Element(ns + "Server")?.Value),
                        "ShowMessage" => action.Element(ns + "Title") == null || action.Element(ns + "Body") == null,
                        _ => true
                    })) throw new InvalidDataException("Invalid required task Actions shape.");
                var exec = actions.FirstOrDefault(action => action.Name == ns + "Exec");
                artifacts.Add(new PersistenceArtifact
                {
                    EvidenceIdentity = identity, CollectorId = Id, Category = "ScheduledTasks", SourceSchemaVersion = 2, Coverage = coverage,
                    NativeLocation = task.Path, NativeName = task.Path[(task.Path.LastIndexOf('\\') + 1)..],
                    Command = exec?.Element(ns + "Command")?.Value, Arguments = exec?.Element(ns + "Arguments")?.Value,
                    Principal = root.Element(ns + "Principals")?.ToString(SaveOptions.DisableFormatting),
                    Enabled = root.Element(ns + "Settings")?.Element(ns + "Enabled") is { } enabled ? XmlConvert.ToBoolean(enabled.Value.Trim()) : true,
                    Configuration = new Dictionary<string, PersistenceNativeValue>
                    {
                        ["NativeXml"] = new("TaskSchedulerXml", PersistenceValueState.Known, JsonSerializer.Serialize(task.Xml)),
                        ["OrderedActions"] = new("TaskActions", PersistenceValueState.Known, JsonSerializer.Serialize(actions.Select(action => action.ToString(SaveOptions.DisableFormatting)).ToArray()))
                    }
                });
            }
            catch (Exception ex) when (ex is XmlException or InvalidDataException or ArgumentException or FormatException) { status = PersistenceCollectionStatus.Partial; }
        }
        if (status != PersistenceCollectionStatus.Complete) coverage = coverage with { SourceAvailability = PersistenceSourceAvailability.Unavailable };
        var result = new PersistenceCollectorResult(Id, coverage, status, artifacts.Select(artifact => artifact with { Coverage = coverage }).ToArray(), watch.Elapsed,
            status == PersistenceCollectionStatus.Complete ? snapshot.Diagnostic : "Task coverage incomplete: unreadable/malformed entry, folder, disappearance or bound; no removals inferred.");
        return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>([result]);
    }
}

internal sealed class ScheduledTasksNativeReader(Func<object>? serviceFactory = null) : IScheduledTasksNativeReader
{
    internal static bool IsExpectedNativeFailure(Exception exception) => exception is not InvalidDataException && (exception is COMException or IOException or UnauthorizedAccessException);
    internal const int MaxXmlCharacters = 1024 * 1024;
    private const int MaxTasks = 20000;
    private const int MaxFolders = 1024;
    private const int MaxDepth = 64;
    public ScheduledTasksNativeSnapshot Read(CancellationToken token)
    {
        var tasks = new List<ScheduledTaskNativeEntry>();
        var complete = true;
        var folders = 1;
        var totalXmlCharacters = 0;
        var attemptedTasks = 0;
        var exhausted = false;
        object? service = null;
        object? root = null;
        try
        {
            token.ThrowIfCancellationRequested();
            service = serviceFactory != null ? serviceFactory() : Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service") ?? throw new COMException("Task Scheduler unavailable.")) ?? throw new COMException("Task Scheduler unavailable.");
            ((dynamic)service!).Connect(); // Local computer only; never accepts caller-controlled credentials/host.
            root = ((dynamic)service!).GetFolder("\\");
            Visit((dynamic)root!, 0);
        }
        catch (Exception ex) when (IsExpectedNativeFailure(ex)) { complete = false; }
        finally { Release(root); Release(service); }
        return new(complete ? PersistenceCollectionStatus.Complete : tasks.Count > 0 ? PersistenceCollectionStatus.Partial : PersistenceCollectionStatus.Failed, tasks,
            "Bounded local recursive Task Scheduler enumeration includes hidden tasks where authorized.");

        void Visit(dynamic folder, int depth)
        {
            token.ThrowIfCancellationRequested();
            if (exhausted) return;
            if (depth > MaxDepth) { complete = false; exhausted = true; return; }
            object? entries = null;
            object? children = null;
            try
            {
                entries = folder.GetTasks(1);
                var count = (int)((dynamic)entries).Count;
                if (count > MaxTasks - attemptedTasks) { complete = false; count = Math.Max(0, MaxTasks - attemptedTasks); }
                for (var index = 1; index <= count; index++)
                {
                    if (exhausted) break;
                    token.ThrowIfCancellationRequested(); object? task = null;
                    attemptedTasks++;
                    try
                    {
                        task = ((dynamic)entries)[index];
                        string xml = ((dynamic)task).Xml;
                        // COM materializes Xml before this retained/parser bound; no preallocation guarantee is claimed.
                        if (xml.Length > 32 * 1024 * 1024 - totalXmlCharacters) { complete = false; exhausted = true; break; }
                        totalXmlCharacters += xml.Length;
                        if (xml.Length > MaxXmlCharacters) { complete = false; continue; }
                        string path = ((dynamic)task).Path;
                        if (path.Length > 1024) { complete = false; continue; }
                        tasks.Add(new(path, xml));
                    }
                    catch (Exception ex) when (IsExpectedNativeFailure(ex)) { complete = false; }
                    finally { Release(task); }
                }
                if (attemptedTasks >= MaxTasks || totalXmlCharacters >= 32 * 1024 * 1024) { complete = false; exhausted = true; }
                if (exhausted) return;
                children = folder.GetFolders(0);
                var childCount = (int)((dynamic)children).Count;
                if (childCount > MaxFolders - folders) { complete = false; childCount = Math.Max(0, MaxFolders - folders); }
                for (var index = 1; index <= childCount; index++)
                {
                    if (exhausted) break;
                    if (folders >= MaxFolders || depth >= MaxDepth) { complete = false; exhausted = true; break; }
                    folders++; // Count attempted folder acquisitions, including denied/disappeared entries.
                    token.ThrowIfCancellationRequested(); object? child = null;
                    try { child = ((dynamic)children)[index]; Visit((dynamic)child, depth + 1); }
                    catch (Exception ex) when (IsExpectedNativeFailure(ex)) { complete = false; }
                    finally { Release(child); }
                }
            }
            catch (Exception ex) when (IsExpectedNativeFailure(ex)) { complete = false; }
            finally { Release(entries); Release(children); }
        }
    }
    private static void Release(object? value) { if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value); }
}
