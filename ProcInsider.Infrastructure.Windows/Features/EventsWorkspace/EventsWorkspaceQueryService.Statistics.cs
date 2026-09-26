using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Models;
using ProcInsider.Services.Events;

namespace ProcInsider.Services;

internal sealed partial class EventsWorkspaceQueryService
{
    private sealed record StatisticsCache(string Filter, IEventsTextProjection? Projection, EventsFieldStatistics Result);
    private StatisticsCache? _statisticsCache;

    public Task<EventsFieldStatistics> FieldStatisticsAsync(EventsFilter filter, EventsStatisticsScope scope,
        IProgress<EventsStatisticsProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(scope)) throw new ArgumentOutOfRangeException(nameof(scope));
        var effective = scope == EventsStatisticsScope.EntireCapture ? new EventsFilter() : filter;
        Validate(effective, 0, 1);
        // Criteria and text projection are immutable request inputs, as for listing queries.
        var key = JsonSerializer.Serialize(effective with { TextProjection = null });
        var projection = effective.Columns.Any(p => p.Value.IsActive && p.Key is EventSort.Details or EventSort.Description)
            ? effective.TextProjection : null;
        return RunAsync(() =>
        {
            if (_statisticsCache is { } cache && cache.Filter == key && ReferenceEquals(cache.Projection, projection) && cache.Result.Scope == scope)
            {
                progress?.Report(new(cache.Result.EligibleEvents, cache.Result.EligibleEvents));
                return cache.Result;
            }
            if (!CaptureWritePolicy.IsAllowed(_statisticsMode, CaptureWriteCategory.AnalysisMaintenance))
                throw new InvalidOperationException("Disposable Events analysis is unavailable for this capture mode.");
            ConfigureColumns(effective, cancellationToken);
            var result = BuildFieldStatistics(effective, scope, progress, cancellationToken);
            Check(cancellationToken);
            _statisticsCache = new(key, projection, result);
            return result;
        }, cancellationToken);
    }

    private EventsFieldStatistics BuildFieldStatistics(EventsFilter filter, EventsStatisticsScope scope,
        IProgress<EventsStatisticsProgress>? progress, CancellationToken token)
    {
        var watch = Stopwatch.StartNew();
        var total = Count(filter);
        progress?.Report(new(0, total));
        var path = SessionPathService.GetEventsStatisticsPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Never open or attach this writable derived file as evidence. The source remains the assessed read context.
        try
        {
            using var derived = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
            derived.Open();
            SqliteWorkScope.Install(derived);
            using var setup = derived.CreateCommand();
            // 2 MiB page cache, no mmap, no cardinality-sized temporary sort. PK order supports bounded top-ten scans.
            setup.CommandText = """
                PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;
                CREATE TABLE Fields(Id TEXT PRIMARY KEY COLLATE BINARY, Type TEXT NOT NULL, Path TEXT NOT NULL, N INTEGER NOT NULL) WITHOUT ROWID;
                CREATE TABLE Counts(Field TEXT COLLATE BINARY NOT NULL, Value TEXT COLLATE BINARY NOT NULL, N INTEGER NOT NULL,
                    PRIMARY KEY(Field,Value)) WITHOUT ROWID;
                """;
            setup.ExecuteNonQuery();
            long processed = 0, available = 0, partial = 0, failed = 0;
            using (var transaction = derived.BeginTransaction())
            using (var fieldInsert = derived.CreateCommand())
            using (var valueInsert = derived.CreateCommand())
            // TEXT substr stops at NUL and could turn malformed XML into a valid prefix. BLOB slicing retains
            // NULs. Four bytes per UTF-16 unit plus a sentinel exceed every accepted extractor payload, so
            // a byte-truncated payload must still exceed the parser's character limit and publish no fields.
            using (var scan = Command($"SELECT e.EventCode,COALESCE(e.RawProvider,''),COALESCE(e.RawLogName,''),COALESCE(CAST(substr(CAST(COALESCE(e.Details,'') AS BLOB),1,{NativeEventFieldExtractor.MaximumCharacters * 4 + 4}) AS TEXT),'') FROM ew_events e WHERE {Predicate(filter)};", filter))
            {
                fieldInsert.Transaction = valueInsert.Transaction = transaction;
                fieldInsert.CommandText = "INSERT INTO Fields VALUES($id,$type,$path,1) ON CONFLICT(Id) DO UPDATE SET N=N+1;";
                valueInsert.CommandText = "INSERT INTO Counts VALUES($id,$value,1) ON CONFLICT(Field,Value) DO UPDATE SET N=N+1;";
                foreach (var name in new[] { "$id", "$type", "$path" }) fieldInsert.Parameters.AddWithValue(name, "");
                foreach (var name in new[] { "$id", "$value" }) valueInsert.Parameters.AddWithValue(name, "");
                using var reader = scan.ExecuteReader();
                while (reader.Read())
                {
                    Check(token);
                    var extraction = NativeEventFieldExtractor.Extract(reader.GetString(3), reader.IsDBNull(0) ? null : reader.GetInt32(0),
                        reader.GetString(1), reader.GetString(2), token);
                    if (extraction.Status == EventFieldExtractionStatus.Available) available++;
                    else if (extraction.Status == EventFieldExtractionStatus.Partial) partial++;
                    else failed++;
                    if (extraction.EventType is { } type)
                    {
                        var serializedType = JsonSerializer.Serialize(type);
                        foreach (var group in extraction.Fields.GroupBy(f => f.Path, StringComparer.Ordinal))
                        {
                            Check(token);
                            var id = JsonSerializer.Serialize(new[] { serializedType, group.Key });
                            fieldInsert.Parameters["$id"].Value = valueInsert.Parameters["$id"].Value = id;
                            fieldInsert.Parameters["$type"].Value = serializedType;
                            fieldInsert.Parameters["$path"].Value = group.Key;
                            fieldInsert.ExecuteNonQuery();
                            foreach (var value in group.Select(f => f.Value).Distinct(StringComparer.Ordinal))
                            {
                                valueInsert.Parameters["$value"].Value = value;
                                valueInsert.ExecuteNonQuery();
                            }
                        }
                    }
                    if (++processed % 128 == 0) progress?.Report(new(processed, total));
                }
                Check(token);
                transaction.Commit();
            }
            var fields = new List<EventFieldStatistics>();
            using var fieldRead = derived.CreateCommand();
            fieldRead.CommandText = "SELECT Id,Type,Path,N FROM Fields ORDER BY Id;";
            using var fieldReader = fieldRead.ExecuteReader();
            while (fieldReader.Read())
            {
                Check(token);
                using var values = derived.CreateCommand();
                values.CommandText = "SELECT Value,N FROM Counts WHERE Field=$id ORDER BY Value COLLATE BINARY;";
                values.Parameters.AddWithValue("$id", fieldReader.GetString(0));
                using var valueReader = values.ExecuteReader();
                long distinct = 0;
                var top = new List<EventFieldFrequency>(11);
                while (valueReader.Read())
                {
                    Check(token);
                    distinct++;
                    var value = new EventFieldFrequency(valueReader.GetString(0), valueReader.GetInt64(1));
                    var index = top.FindIndex(v => value.EventCount > v.EventCount ||
                        value.EventCount == v.EventCount && string.CompareOrdinal(value.Value, v.Value) < 0);
                    top.Insert(index < 0 ? top.Count : index, value);
                    if (top.Count > 10) top.RemoveAt(10);
                }
                fields.Add(new(JsonSerializer.Deserialize<NativeEventType>(fieldReader.GetString(1))!, fieldReader.GetString(2),
                    fieldReader.GetInt64(3), distinct, top.AsReadOnly()));
            }
            progress?.Report(new(processed, total));
            return new(_binding, scope, total, available, partial, failed, fields.AsReadOnly(), new FileInfo(path).Length,
                watch.Elapsed, EventFieldExtraction.ExtractorVersion, _completeness!);
        }
        finally
        {
            // No pooling or durable result DB: successful, failed and canceled operations discard exact owned scratch.
            File.Delete(path);
        }
    }
}
