using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>Append-only structured bodies and exact read receipts in the store-owned transaction.</summary>
internal sealed class ForensicArtifactWriteService(SqliteWriteTransactionContext context)
{
    internal const string ReadRecordType = "ForensicSourceReadV1";
    internal static readonly (string Name, string Type)[] Columns =
    [ ("StructuredPayloadVersion","INTEGER"), ("Category","TEXT"), ("ParserId","TEXT"), ("ParserVersion","TEXT"),
      ("ParserSettingsJson","TEXT"), ("PropertiesJson","TEXT"), ("InputByteCount","INTEGER"), ("InputSha256","TEXT"),
      ("ResultSha256","TEXT"), ("OriginalFileRetained","INTEGER"), ("OutputKey","TEXT"), ("SourcePathSemantics","INTEGER") ];
    internal const string IndexSql = """
        CREATE UNIQUE INDEX IF NOT EXISTS IX_ForensicReadAttempt ON RawRecords(ExternalRecordId) WHERE RecordType='ForensicSourceReadV1';
        CREATE INDEX IF NOT EXISTS IX_Artifacts_StructuredScope ON Artifacts(StructuredPayloadVersion,EvidenceSessionId,CaptureId,HostId,ArtifactId);
        """;

    internal ForensicArtifactAppendResult Append(IReadOnlyList<ForensicReadAttempt> reads, CancellationToken token)
    {
        var frozen = ForensicArtifactContract.Freeze(reads);
        var persisted = 0; var duplicates = 0; var reused = 0;
        context.Execute(() =>
        {
            foreach (var read in frozen)
            {
                token.ThrowIfCancellationRequested();
                var sourceId = ValidateRun(read);
                var attemptKey = "forensic-read-v1-" + ForensicArtifactContract.AttemptIdentity(read);
                var receipt = JsonSerializer.Serialize(new ReadReceipt(read with { Outputs=[] }, read.Outputs.Select(output =>
                    new ResultReference("forensic-result-v1-"+ForensicArtifactContract.ResultIdentity(read,output), output.OutputKey, ForensicArtifactContract.Hash(JsonSerializer.Serialize(output)))).ToArray()));
                var receiptHash = ForensicArtifactContract.Hash(receipt);
                var readFields = ScopeFields(read.Scope);
                readFields.AddRange([("SourceId",sourceId), ("SourceRunId",read.SourceRunId), ("IngestionJobId",read.IngestionJobId.ToString("D")),
                    ("ExternalRecordId",attemptKey), ("TimestampUtc",Utc(read.ReadCompletedUtc)), ("RecordType",ReadRecordType),
                    ("PayloadJson",receipt), ("PayloadText",null), ("PayloadHash",receiptHash)]);
                long rawId;
                using (var existing = Command("SELECT RawRecordId FROM RawRecords WHERE ExternalRecordId=$id", ("id",attemptKey)))
                    rawId = existing.ExecuteScalar() is long found ? found : 0;
                var replay = rawId != 0;
                if (replay) Verify("RawRecords", "RawRecordId", rawId, readFields);
                else
                {
                    var insertFields = readFields.Concat(new[] { ("CreatedUtc", (object?)Utc(read.ReadCompletedUtc)) }).ToList();
                    using var insert = Insert("RawRecords", insertFields, " RETURNING RawRecordId");
                    rawId = Convert.ToInt64(insert.ExecuteScalar(), CultureInfo.InvariantCulture); persisted++;
                }
                foreach (var output in read.Outputs)
                {
                    token.ThrowIfCancellationRequested();
                    var artifactId = "forensic-result-v1-" + ForensicArtifactContract.ResultIdentity(read, output);
                    var body = JsonSerializer.Serialize(output);
                    var fields = ScopeFields(read.Scope);
                    fields.AddRange([("ArtifactType",output.ArtifactType), ("TimestampUtc",output.PrimaryTimeUtc.HasValue ? Utc(output.PrimaryTimeUtc.Value) : null),
                        ("Name",output.Name), ("Path",read.SourcePath), ("Summary",output.Summary), ("Hash",read.InputSha256),
                        ("StructuredPayloadVersion",output.PayloadVersion), ("Category",output.Category), ("ParserId",read.Parser.ParserId),
                        ("ParserVersion",read.Parser.ParserVersion), ("ParserSettingsJson",read.Parser.SettingsJson), ("PropertiesJson",output.PropertiesJson),
                        ("InputByteCount",read.InputByteCount), ("InputSha256",read.InputSha256), ("ResultSha256",ForensicArtifactContract.Hash(body)),
                        ("OriginalFileRetained",0), ("OutputKey",output.OutputKey), ("SourcePathSemantics",(int)read.PathSemantics)]);
                    using var exists = Command("SELECT SourceRunId,IngestionJobId,RawRecordId,Path,SourceId FROM Artifacts WHERE ArtifactId=$id", ("id",artifactId));
                    using var reader = exists.ExecuteReader();
                    if (reader.Read())
                    {
                        var originalRun = reader.GetString(0); var originalJob = reader.GetString(1); var originalReadId = reader.GetInt64(2);
                        var originalPath = reader.GetString(3); var originalSourceId=reader.GetInt32(4); reader.Close();
                        if (ForensicArtifactContract.PathKey(originalPath, read.PathSemantics) != ForensicArtifactContract.PathKey(read.SourcePath, read.PathSemantics))
                            throw new InvalidDataException("Conflicting forensic source path identity.");
                        fields[fields.FindIndex(p=>p.Item1=="Path")] = ("Path", originalPath); // Retain first raw spelling on reusable body.
                        Verify("Artifacts", "ArtifactId", artifactId, fields);
                        if (VerifyOriginalReceipt(originalReadId, originalRun, originalJob, artifactId, output)!=originalSourceId)
                            throw new InvalidDataException("Reusable forensic body has a contradictory registered source.");
                        reused++;
                    }
                    else
                    {
                        reader.Close();
                        if (replay) throw new InvalidDataException("Forensic replay is missing its original result body.");
                        fields.AddRange([("ArtifactId",artifactId), ("SourceId",sourceId), ("SourceRunId",read.SourceRunId),
                            ("IngestionJobId",read.IngestionJobId.ToString("D")), ("RawRecordId",rawId), ("ProcessKey",null), ("ParentArtifactId",null),
                            ("CreatedUtc",Utc(read.ReadCompletedUtc)), ("UpdatedUtc",Utc(read.ReadCompletedUtc))]);
                        using var insert = Insert("Artifacts",fields); insert.ExecuteNonQuery(); persisted++;
                    }
                    var relationId = "forensic-lineage-v1-" + ForensicArtifactContract.Hash(attemptKey + ":" + artifactId);
                    var lineage = ScopeFields(read.Scope);
                    lineage.AddRange([("RelationId",relationId), ("DecisionKey",relationId), ("FromKind",EvidenceReferenceKind.RawRecord.ToString()), ("FromId",rawId.ToString(CultureInfo.InvariantCulture)),
                        ("ToKind",EvidenceReferenceKind.GenericArtifact.ToString()), ("ToId",artifactId), ("RelationType",EvidenceRelationType.DerivedFrom.ToString()), ("CorrelationState","Exact"),
                        ("CorrelationMethod","ParserResultForRead"), ("Confidence",1.0), ("CandidateCount",1), ("CorrelationDiagnostics",read.Diagnostic),
                        ("SourceRunId",read.SourceRunId), ("IngestionJobId",read.IngestionJobId.ToString("D")), ("RawInputId",rawId.ToString(CultureInfo.InvariantCulture)),
                        ("ObservedFromUtc",Utc(read.ReadStartedUtc)), ("ObservedToUtc",Utc(read.ReadCompletedUtc)), ("ValidFromUtc",null), ("ValidToUtc",null),
                        ("ResolverName",read.Parser.ParserId), ("ResolverVersion",read.Parser.ParserVersion), ("CreatedUtc",Utc(read.ReadCompletedUtc)),
                        ("UpdatedUtc",Utc(read.ReadCompletedUtc)), ("Status","Active"), ("SupersededByRelationId",null), ("AnalystAnnotationId",null)]);
                    if (replay) Verify("EvidenceRelations","RelationId",relationId,lineage);
                    else { using var insert=Insert("EvidenceRelations",lineage); insert.ExecuteNonQuery(); persisted++; }
                }
                using var count = Command("SELECT COUNT(*) FROM EvidenceRelations WHERE FromKind='RawRecord' AND FromId=$id AND ResolverName=$parser",
                    ("id",rawId.ToString(CultureInfo.InvariantCulture)),("parser",read.Parser.ParserId));
                if (Convert.ToInt64(count.ExecuteScalar()) != read.Outputs.Count) throw new InvalidDataException("Forensic attempt lineage is incomplete or contradictory.");
                if (replay) duplicates++;
            }
        });
        return new(persisted, duplicates, reused);
    }

    private int ValidateRun(ForensicReadAttempt read, bool checkAmbient = true)
    {
        using (var active = Command("SELECT SourceRunId,IngestionJobId FROM WriterProvenanceContext WHERE SingletonId=1"))
        using (var row = active.ExecuteReader())
            if (row.Read() && checkAmbient && (row.GetString(0)!=read.SourceRunId || row.GetString(1)!=read.IngestionJobId.ToString("D")))
                throw new InvalidDataException("Forensic read differs from serialized writer provenance.");
        using var command = Command("""
            SELECT r.SourceId FROM SourceRuns r JOIN IngestionJobs j ON j.JobId=r.IngestionJobId AND j.SourceRunId=r.SourceRunId AND j.SourceId=r.SourceId
            WHERE r.SourceRunId=$run AND r.IngestionJobId=$job AND COALESCE(r.CaseId,'')=$case AND r.EvidenceSessionId=$session
              AND r.CaptureId=$capture AND r.SourceIdentityId=$source AND r.HostId=$host AND r.ExecutionRootId=$root
              AND COALESCE(j.CaseId,'')=$case AND j.EvidenceSessionId=$session AND j.CaptureId=$capture AND j.HostId=$host AND j.ExecutionRootId=$root
              AND r.EvidenceSessionId=(SELECT Value FROM SchemaInfo WHERE Key='EvidenceSessionId');
            """,("run",read.SourceRunId), ("job",read.IngestionJobId.ToString("D")), ("case",read.Scope.CaseId), ("session",read.Scope.EvidenceSessionId),
            ("capture",read.Scope.CaptureId), ("source",read.Scope.SourceIdentityId), ("host",read.Scope.HostId), ("root",read.Scope.ExecutionRootId));
        return command.ExecuteScalar() is long sourceId ? checked((int)sourceId) : throw new InvalidDataException("Forensic read requires the exact registered source run, job and session.");
    }

    private int VerifyOriginalReceipt(long id, string run, string job, string artifactId, ForensicArtifactOutput output)
    {
        using var command = Command("SELECT SourceRunId,IngestionJobId,PayloadJson,PayloadHash,RecordType FROM RawRecords WHERE RawRecordId=$id",("id",id));
        using var row=command.ExecuteReader();
        if (!row.Read() || row.GetString(0)!=run || row.GetString(1)!=job || row.GetString(4)!=ReadRecordType || ForensicArtifactContract.Hash(row.GetString(2))!=row.GetString(3))
            throw new InvalidDataException("Reusable forensic body has no verified original receipt.");
        var originalPayload = row.GetString(2);
        var receipt = JsonSerializer.Deserialize<ReadReceipt>(originalPayload)!;
        row.Close();
        var original = ForensicArtifactContract.Freeze([receipt.Read]).Single();
        if (original.Outputs.Count!=0 || JsonSerializer.Serialize(new ReadReceipt(original,receipt.Results))!=originalPayload ||
            original.SourceRunId!=run || original.IngestionJobId.ToString("D")!=job || original.Status!=ForensicReadStatus.Succeeded ||
            original.ParserStatus is not (ForensicParseStatus.Succeeded or ForensicParseStatus.Partial) ||
            "forensic-result-v1-"+ForensicArtifactContract.ResultIdentity(original,output)!=artifactId ||
            !receipt.Results.Any(reference=>reference.ArtifactId==artifactId && reference.OutputKey==output.OutputKey && reference.ResultSha256==ForensicArtifactContract.Hash(JsonSerializer.Serialize(output))))
            throw new InvalidDataException("Reusable forensic body contradicts its original parser receipt.");
        var sourceId = ValidateRun(original, checkAmbient:false);
        var rawFields = ScopeFields(original.Scope);
        rawFields.AddRange([("SourceId",sourceId), ("SourceRunId",run), ("IngestionJobId",job),
            ("ExternalRecordId","forensic-read-v1-"+ForensicArtifactContract.AttemptIdentity(original)),
            ("TimestampUtc",Utc(original.ReadCompletedUtc)), ("CreatedUtc",Utc(original.ReadCompletedUtc)),
            ("PayloadText",null)]);
        Verify("RawRecords", "RawRecordId", id, rawFields);
        Verify("Artifacts", "ArtifactId", artifactId, [("CreatedUtc",Utc(original.ReadCompletedUtc)), ("UpdatedUtc",Utc(original.ReadCompletedUtc)), ("ProcessKey",null), ("ParentArtifactId",null)]);
        return sourceId;
    }

    private void Verify(string table, string key, object id, List<(string, object?)> fields)
    {
        using var command=Command($"SELECT {string.Join(',',fields.Select(p=>p.Item1))} FROM {table} WHERE {key}=$id",("id",id));
        using var row=command.ExecuteReader();
        if (!row.Read()) throw new InvalidDataException("Missing immutable forensic row.");
        for(var i=0;i<fields.Count;i++)
        {
            var expected=fields[i].Item2;
            if (expected==null ? !row.IsDBNull(i) : row.IsDBNull(i) || Convert.ToString(row.GetValue(i),CultureInfo.InvariantCulture)!=Convert.ToString(expected,CultureInfo.InvariantCulture))
                throw new InvalidDataException("Conflicting immutable forensic replay: "+fields[i].Item1);
        }
    }

    private SqliteCommand Insert(string table,List<(string,object?)> fields,string suffix="") =>
        Command($"INSERT INTO {table}({string.Join(',',fields.Select(p=>p.Item1))}) VALUES({string.Join(',',fields.Select((_,i)=>"$p"+i))}){suffix}",
            fields.Select((p,i)=>("p"+i,p.Item2)).ToArray());
    private SqliteCommand Command(string sql,params (string,object?)[] parameters)
    {
        var command=context.CreateCommand(sql);
        foreach(var (name,value) in parameters) SqliteWriteTransactionContext.Add(command,"$"+name,value);
        return command;
    }
    private static string Utc(DateTime time)=>time.ToString("O",CultureInfo.InvariantCulture);
    private static List<(string,object?)> ScopeFields(EvidenceIdentity s)=>
        [("CaseId",s.CaseId), ("EvidenceSessionId",s.EvidenceSessionId), ("CaptureId",s.CaptureId), ("SourceIdentityId",s.SourceIdentityId), ("HostId",s.HostId), ("ExecutionRootId",s.ExecutionRootId)];
    private sealed record ReadReceipt(ForensicReadAttempt Read, IReadOnlyList<ResultReference> Results);
    private sealed record ResultReference(string ArtifactId, string OutputKey, string ResultSha256);
}
