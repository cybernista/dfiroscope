using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    private Investigation PublishInvestigationResult(InvestigationPublication publication, CancellationToken ct,
        AgentToolSession? checkedSession = null, Func<bool>? isCurrent = null,
        IReadOnlyList<AiEvidenceReference>? visibleReferences = null)
    {
        if (publication is null || string.IsNullOrWhiteSpace(publication.InvestigationId) ||
            publication.Summary is null || publication.Summary.Length > 20_000 ||
            publication.OpenQuestions is null || publication.OpenQuestions.Count > 100 ||
            publication.OpenQuestions.Any(q => string.IsNullOrWhiteSpace(q) || q.Length > 2000) ||
            publication.FollowUpTasks is null || publication.FollowUpTasks.Count > 100 ||
            publication.Findings is null || publication.Findings.Count > 100 ||
            publication.Hypotheses is null || publication.Hypotheses.Count > 100 ||
            publication.EvidenceLinks is null || publication.EvidenceLinks.Count > 256 ||
            publication.InvestigationStatus is not (InvestigationState.Completed or InvestigationState.NeedsEvidence or
                InvestigationState.NeedsHumanDecision or InvestigationState.Failed or InvestigationState.Cancelled) ||
            publication.CompletedExecution is null || publication.VisibleMessage is null)
            throw new ArgumentException("Investigation publication is invalid.");
        if (visibleReferences is { Count: > 50 } ||
            visibleReferences is not null && checkedSession is null)
            throw new ArgumentException("Checked visible citations are invalid.");
        ValidateExecution(publication.CompletedExecution, start: false);
        if (publication.CompletedExecution.Status == AgentExecutionState.Completed &&
            publication.InvestigationStatus is InvestigationState.Failed or InvestigationState.Cancelled)
            throw new ArgumentException("Successful execution cannot publish failed investigation state.");
        if (publication.CompletedExecution.Status switch
            {
                AgentExecutionState.Failed => publication.InvestigationStatus != InvestigationState.Failed,
                AgentExecutionState.Cancelled => publication.InvestigationStatus != InvestigationState.Cancelled,
                AgentExecutionState.Interrupted => publication.InvestigationStatus != InvestigationState.Failed,
                _ => false
            })
            throw new ArgumentException("Execution and investigation terminal outcomes disagree.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var inv = ReadInvestigation(connection, tx, publication.InvestigationId) ??
                throw new InvalidOperationException("Investigation is unavailable.");
            var running = ReadExecution(connection, tx, publication.CompletedExecution.Id) ??
                throw new InvalidOperationException("Execution is unavailable.");
            var conversation = checkedSession is null ? null :
                LoadConversationForWrite(connection, tx, running.ConversationId);
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            if (running.Status != AgentExecutionState.Running)
            {
                if (!PublicationRetryMatches(connection, tx, inv, running, publication) ||
                    visibleReferences is not null && !MessageEvidenceMatches(connection, tx,
                        publication.VisibleMessage.Id, visibleReferences))
                    throw new InvalidOperationException("Publication retry conflicts with committed result.");
                tx.Commit(); return inv;
            }
            if (running.Status != AgentExecutionState.Running || inv.Status != InvestigationState.Investigating ||
                running.InvestigationId != inv.Id || running.ConversationId != inv.ConversationId ||
                !SameExecutionIdentity(running, publication.CompletedExecution) ||
                publication.CompletedExecution.IterationCount < running.IterationCount ||
                !UsageIsMonotonic(running.TokenUsage, publication.CompletedExecution.TokenUsage) ||
                AiExecutionLifetime.GetOwnerState(running.Owner) != AiExecutionOwnerState.Active)
                throw new InvalidOperationException("Investigation publication is not from its active execution.");
            if (publication.CompletedExecution.CompletedUtc < inv.UpdatedUtc)
                throw new InvalidOperationException("Investigation result predates its latest update.");
            AssertNoRunningTools(connection, tx, running.Id);
            AssertToolCallCount(connection, tx, publication.CompletedExecution);
            AssertToolOutcomeChronology(connection, tx, publication.CompletedExecution);
            if (publication.TaskStatus is not null)
            {
                if (running.TaskId is null || publication.TaskStatus is not
                    (InvestigationTaskState.Completed or InvestigationTaskState.NeedsEvidence or InvestigationTaskState.Failed or InvestigationTaskState.Cancelled))
                    throw new InvalidOperationException("Task outcome is invalid.");
                var task = ReadTask(connection, tx, running.TaskId) ?? throw new InvalidOperationException("Task is unavailable.");
                if (task.InvestigationId != inv.Id || task.Status != InvestigationTaskState.Running ||
                    publication.TaskResultSummary is null || publication.TaskResultSummary.Length > 4000 ||
                    publication.CompletedExecution.CompletedUtc < task.CreatedUtc)
                    throw new InvalidOperationException("Task cannot receive this outcome.");
            }
            else if (running.TaskId is not null) throw new InvalidOperationException("Running task requires a published outcome.");
            ValidatePublicationLinkOwners(publication);
            AssertDesiredEvidenceLinksPreserveExisting(connection, tx, publication);
            foreach (var task in publication.FollowUpTasks)
            {
                ValidateTask(task, isInitial: false);
                if (task.InvestigationId != inv.Id || task.CreatedByExecutionId != running.Id ||
                    task.Status != InvestigationTaskState.Pending || task.CompletedUtc is not null ||
                    task.CreatedUtc < running.StartedUtc || task.CreatedUtc > publication.CompletedExecution.CompletedUtc ||
                    task.ParentTaskId is not null && (ReadTask(connection, tx, task.ParentTaskId) is not { } parent ||
                        parent.InvestigationId != inv.Id || task.CreatedUtc < parent.CreatedUtc))
                    throw new InvalidOperationException("Follow-up task has incorrect provenance or parent.");
                InsertTask(connection, tx, task);
            }
            foreach (var finding in publication.Findings)
            {
                ValidateFinding(finding, inv.Id);
                var existingFinding = ReadFindingById(connection, tx, finding.Id);
                if (existingFinding is null)
                {
                    if (finding.CreatedByExecutionId != running.Id || finding.AssessedByExecutionId is not null && finding.AssessedByExecutionId != running.Id)
                        throw new InvalidOperationException("New finding requires current execution provenance.");
                    if (finding.CreatedUtc < running.StartedUtc || finding.CreatedUtc > publication.CompletedExecution.CompletedUtc)
                        throw new InvalidOperationException("Finding creation is outside its execution.");
                    Execute(connection, tx, """
                        INSERT INTO AiInvestigationFindings(Id,InvestigationId,Title,Claim,Description,Severity,Confidence,
                            VerificationStatus,CreatedByExecutionId,CreatedUtc,AnalystVerifiedBy,AnalystVerifiedUtc,AssessedByExecutionId)
                        VALUES($Id,$Inv,$Title,$Claim,$Description,$Severity,$Confidence,$Verification,$Execution,$Utc,NULL,NULL,$Assessor);
                        """, ("$Id", finding.Id), ("$Inv", inv.Id), ("$Title", finding.Title), ("$Claim", finding.Claim),
                        ("$Description", finding.Description), ("$Severity", finding.Severity.ToString()),
                        ("$Confidence", finding.Confidence), ("$Verification", finding.VerificationStatus.ToString()),
                        ("$Execution", running.Id), ("$Utc", finding.CreatedUtc), ("$Assessor", finding.AssessedByExecutionId));
                }
                else
                {
                    if (existingFinding.InvestigationId != inv.Id || existingFinding.VerificationStatus == FindingVerificationState.AnalystVerified ||
                        existingFinding.Title != finding.Title || existingFinding.Claim != finding.Claim ||
                        existingFinding.Description != finding.Description || existingFinding.Severity != finding.Severity ||
                        existingFinding.CreatedByExecutionId != finding.CreatedByExecutionId ||
                        existingFinding.CreatedUtc != finding.CreatedUtc || finding.AssessedByExecutionId != running.Id)
                        throw new InvalidOperationException("Existing finding claim or verification is immutable.");
                    Execute(connection, tx, """
                        UPDATE AiInvestigationFindings SET VerificationStatus=$Verification,Confidence=$Confidence,
                            AssessedByExecutionId=$Execution WHERE Id=$Id AND VerificationStatus<>'AnalystVerified';
                        """, ("$Id", finding.Id), ("$Verification", finding.VerificationStatus.ToString()),
                        ("$Confidence", finding.Confidence), ("$Execution", running.Id));
                }
            }
            foreach (var hypothesis in publication.Hypotheses)
            {
                ValidateHypothesis(hypothesis, inv.Id);
                var existingHypothesis = ReadHypothesisById(connection, tx, hypothesis.Id);
                if (existingHypothesis is null)
                {
                    if (hypothesis.CreatedByExecutionId != running.Id ||
                        hypothesis.UpdatedByExecutionId is not null && hypothesis.UpdatedByExecutionId != running.Id)
                        throw new InvalidOperationException("New hypothesis requires current execution provenance.");
                    if (hypothesis.CreatedUtc < running.StartedUtc ||
                        hypothesis.UpdatedUtc > publication.CompletedExecution.CompletedUtc)
                        throw new InvalidOperationException("Hypothesis creation is outside its execution.");
                    Execute(connection, tx, """
                        INSERT INTO AiInvestigationHypotheses(Id,InvestigationId,Statement,Status,Confidence,
                            CreatedByExecutionId,CreatedUtc,UpdatedUtc,UpdatedByExecutionId)
                        VALUES($Id,$Inv,$Statement,$Status,$Confidence,$Execution,$Created,$Updated,$Updater);
                        """, ("$Id", hypothesis.Id), ("$Inv", inv.Id), ("$Statement", hypothesis.Statement),
                        ("$Status", hypothesis.Status.ToString()), ("$Confidence", hypothesis.Confidence),
                        ("$Execution", running.Id), ("$Created", hypothesis.CreatedUtc),
                        ("$Updated", hypothesis.UpdatedUtc), ("$Updater", hypothesis.UpdatedByExecutionId));
                }
                else
                {
                    if (existingHypothesis.InvestigationId != inv.Id || existingHypothesis.Statement != hypothesis.Statement ||
                        existingHypothesis.CreatedByExecutionId != hypothesis.CreatedByExecutionId ||
                        existingHypothesis.CreatedUtc != hypothesis.CreatedUtc || hypothesis.UpdatedUtc < existingHypothesis.UpdatedUtc ||
                        hypothesis.UpdatedByExecutionId != running.Id ||
                        hypothesis.UpdatedUtc < running.StartedUtc ||
                        hypothesis.UpdatedUtc > publication.CompletedExecution.CompletedUtc)
                        throw new InvalidOperationException("Hypothesis update has incorrect provenance.");
                    Execute(connection, tx, """
                        UPDATE AiInvestigationHypotheses SET Status=$Status,Confidence=$Confidence,
                            UpdatedUtc=$Updated,UpdatedByExecutionId=$Execution WHERE Id=$Id;
                        """, ("$Id", hypothesis.Id), ("$Status", hypothesis.Status.ToString()),
                        ("$Confidence", hypothesis.Confidence), ("$Updated", hypothesis.UpdatedUtc),
                        ("$Execution", running.Id));
                }
            }
            foreach (var link in publication.EvidenceLinks)
                InsertEvidenceLink(connection, tx, link, link.Owner, link.OwnerId, running, ct);
            InsertVisibleMessage(connection, tx, publication.VisibleMessage, publication.CompletedExecution);
            if (visibleReferences is not null)
                foreach (var reference in visibleReferences)
                {
                    ct.ThrowIfCancellationRequested();
                    if (reference is null || checkedSession?.AdmitReference(reference) != true)
                        throw new InvalidOperationException("Investigation citation was not admitted by its checked execution.");
                    ValidateReference(reference);
                    if (!ReferenceWithinScope(conversation!.Scope, reference.Identity) &&
                        !ToolEvidenceBelongsToExecution(connection, tx, running.Id, reference))
                        throw new InvalidOperationException("Related citation was not persisted by this execution's Tool call.");
                    InsertOrVerifyReference(connection, tx, reference);
                    Execute(connection, tx,
                        "INSERT INTO AiMessageEvidence(MessageId,ReferenceId) VALUES($Message,$Reference);",
                        ("$Message", publication.VisibleMessage.Id), ("$Reference", reference.ReferenceId));
                }
            if (running.TaskId is not null)
                Execute(connection, tx, """
                    UPDATE AiInvestigationTasks SET Status=$Status,CompletedUtc=$Utc,ResultSummary=$Summary
                    WHERE Id=$Id AND Status='Running';
                    """, ("$Status", publication.TaskStatus!.Value.ToString()), ("$Utc", publication.CompletedExecution.CompletedUtc),
                    ("$Summary", publication.TaskResultSummary), ("$Id", running.TaskId));
            Execute(connection, tx, """
                UPDATE AiInvestigations SET Status=$Status,Summary=$Summary,OpenQuestionsJson=$Questions,
                    UpdatedUtc=$Utc,CompletedUtc=$Completed WHERE Id=$Id AND Status='Investigating';
                """, ("$Id", inv.Id), ("$Status", publication.InvestigationStatus.ToString()),
                ("$Summary", publication.Summary), ("$Questions", JsonSerializer.Serialize(publication.OpenQuestions)),
                ("$Utc", publication.CompletedExecution.CompletedUtc),
                ("$Completed", publication.InvestigationStatus == InvestigationState.Completed ? publication.CompletedExecution.CompletedUtc : null));
            UpdateExecutionTerminal(connection, tx, publication.CompletedExecution);
            ct.ThrowIfCancellationRequested();
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            tx.Commit();
            return ReadInvestigation(connection, null, inv.Id)!;
        }
    }

    private AgentExecution FinishExecution(AgentExecution terminal, AiConversationMessage visibleMessage,
        CancellationToken ct, AgentToolSession? checkedSession = null, Func<bool>? isCurrent = null,
        IReadOnlyList<AiEvidenceReference>? references = null)
    {
        ValidateExecution(terminal, start: false);
        if (references is { Count: > 50 } || references is { } && checkedSession is null)
            throw new ArgumentException("Checked conversation citations are invalid.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var running = ReadExecution(connection, tx, terminal.Id) ?? throw new InvalidOperationException("Execution is unavailable.");
            var conversation = checkedSession is null ? null :
                LoadConversationForWrite(connection, tx, running.ConversationId);
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            if (running.Status != AgentExecutionState.Running)
            {
                if (running != terminal || LoadMessageForWrite(connection, tx, visibleMessage.Id) != visibleMessage)
                    throw new InvalidOperationException("Execution result retry conflicts with committed audit.");
                if (references is not null && !MessageEvidenceMatches(connection, tx, visibleMessage.Id, references))
                    throw new InvalidOperationException("Conversation citation retry conflicts with committed result.");
                tx.Commit(); return running;
            }
            if (running.InvestigationId is not null || running.Status != AgentExecutionState.Running ||
                !SameExecutionIdentity(running, terminal) ||
                terminal.IterationCount < running.IterationCount ||
                !UsageIsMonotonic(running.TokenUsage, terminal.TokenUsage) ||
                AiExecutionLifetime.GetOwnerState(running.Owner) != AiExecutionOwnerState.Active)
                throw new InvalidOperationException("Conversation execution cannot transition.");
            AssertNoRunningTools(connection, tx, running.Id);
            AssertToolCallCount(connection, tx, terminal);
            AssertToolOutcomeChronology(connection, tx, terminal);
            InsertVisibleMessage(connection, tx, visibleMessage, terminal);
            if (references is not null)
                foreach (var reference in references)
                {
                    ct.ThrowIfCancellationRequested();
                    if (reference is null || checkedSession?.AdmitReference(reference) != true)
                        throw new InvalidOperationException("Conversation citation was not admitted by its checked execution.");
                    ValidateReference(reference);
                    if (!ReferenceWithinScope(conversation!.Scope, reference.Identity) &&
                        !ToolEvidenceBelongsToExecution(connection, tx, terminal.Id, reference))
                        throw new InvalidOperationException("Related citation was not persisted by this execution's Tool call.");
                    InsertOrVerifyReference(connection, tx, reference);
                    Execute(connection, tx,
                        "INSERT INTO AiMessageEvidence(MessageId,ReferenceId) VALUES($Message,$Reference);",
                        ("$Message", visibleMessage.Id), ("$Reference", reference.ReferenceId));
                }
            UpdateExecutionTerminal(connection, tx, terminal);
            ct.ThrowIfCancellationRequested();
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            tx.Commit(); return terminal;
        }
    }

    private static bool ToolEvidenceBelongsToExecution(SqliteConnection connection, SqliteTransaction tx,
        string executionId, AiEvidenceReference reference)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = """
            SELECT 1 FROM AiToolCallEvidence e
            JOIN AiAgentToolCalls t ON t.Id=e.ToolCallId
            WHERE t.AgentExecutionId=$Execution AND e.ReferenceId=$Reference LIMIT 1;
            """;
        Add(command, "$Execution", executionId);
        Add(command, "$Reference", reference.ReferenceId);
        return command.ExecuteScalar() is not null &&
            LoadReference(connection, tx, reference.ReferenceId) == reference;
    }

    private static bool MessageEvidenceMatches(SqliteConnection connection, SqliteTransaction tx,
        string messageId, IReadOnlyList<AiEvidenceReference> references)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT ReferenceId FROM AiMessageEvidence WHERE MessageId=$Message;";
        Add(command, "$Message", messageId);
        var saved = new HashSet<string>(StringComparer.Ordinal);
        using (var reader = command.ExecuteReader())
            while (reader.Read()) saved.Add(reader.GetString(0));
        return references.Select(reference => reference.ReferenceId).Distinct(StringComparer.Ordinal).Count() == references.Count &&
            saved.SetEquals(references.Select(reference => reference.ReferenceId)) &&
            references.All(reference => LoadReference(connection, tx, reference.ReferenceId) == reference);
    }

    private static void InsertVisibleMessage(SqliteConnection connection, SqliteTransaction tx,
        AiConversationMessage message, AgentExecution execution)
    {
        if (message is null || string.IsNullOrWhiteSpace(message.Id) || message.ConversationId != execution.ConversationId ||
            !string.Equals(message.Role, "assistant", StringComparison.OrdinalIgnoreCase) ||
            message.TimestampUtc is not { Kind: DateTimeKind.Utc } || message.TimestampUtc < execution.StartedUtc ||
            message.TimestampUtc > execution.CompletedUtc || message.IsHistorical ||
            message.OriginalProviderKind is not null || message.OriginalBaseUrl is not null ||
            message.OriginalCreatedUtc is not null || message.OriginalProviderName is not null ||
            message.OriginalModelName is not null || message.OriginalErrorText is not null ||
            message.Status is not ("Succeeded" or "Failed" or "Cancelled" or "Interrupted") ||
            message.Content is null || message.Content.Length > 100_000 || message.ErrorText is null || message.ErrorText.Length > ModelDiagnosticRedactor.MaximumDiagnosticCharacters ||
            message.TechnicalDetails is null || message.TechnicalDetails.Length > 48_000 ||
            message.ProviderId != execution.ProviderId || message.ModelId != execution.ModelId)
            throw new ArgumentException("Visible result message is invalid.");
        if (execution.Status == AgentExecutionState.Completed && message.Status != "Succeeded")
            throw new ArgumentException("Completed execution requires succeeded visible result.");
        if (execution.Status == AgentExecutionState.Failed && message.Status != "Failed" ||
            execution.Status == AgentExecutionState.Cancelled && message.Status != "Cancelled" ||
            execution.Status == AgentExecutionState.Interrupted && message.Status != "Interrupted")
            throw new ArgumentException("Visible status must match terminal execution.");
        if (LoadConversationForWrite(connection, tx, execution.ConversationId) is null)
            throw new InvalidOperationException("Execution conversation is unavailable.");
        if (LoadMessageForWrite(connection, tx, message.Id) is not null)
            throw new InvalidOperationException("Message ID is already in use.");
        Execute(connection, tx, """
            INSERT INTO AiMessages(Id,ConversationId,Role,Content,TimestampUtc,ProviderId,ModelId,Status,ErrorText,TechnicalDetails)
            VALUES($Id,$Conversation,$Role,$Content,$Timestamp,$Provider,$Model,$Status,$Error,$Technical);
            """, ("$Id", message.Id), ("$Conversation", message.ConversationId), ("$Role", message.Role),
            ("$Content", message.Content), ("$Timestamp", message.TimestampUtc),
            ("$Provider", message.ProviderId), ("$Model", message.ModelId),
            ("$Status", message.Status), ("$Error", message.ErrorText), ("$Technical", message.TechnicalDetails));
        Execute(connection, tx, "UPDATE AiConversations SET UpdatedUtc=CASE WHEN UpdatedUtc<$Utc THEN $Utc ELSE UpdatedUtc END WHERE Id=$Id;",
            ("$Utc", message.TimestampUtc), ("$Id", message.ConversationId));
    }

    private static void UpdateExecutionTerminal(SqliteConnection connection, SqliteTransaction tx, AgentExecution terminal)
    {
        Execute(connection, tx, """
            UPDATE AiAgentExecutions SET CompletedUtc=$Utc,Status=$Status,IterationCount=$Iterations,
                ToolCallCount=$Calls,InputTokens=$Input,OutputTokens=$Output,TotalTokens=$Total,
                ErrorCategory=$Category,ErrorText=$Error WHERE Id=$Id AND Status='Running';
            """, ("$Id", terminal.Id), ("$Utc", terminal.CompletedUtc), ("$Status", terminal.Status.ToString()),
            ("$Iterations", terminal.IterationCount), ("$Calls", terminal.ToolCallCount),
            ("$Input", terminal.TokenUsage?.InputTokens), ("$Output", terminal.TokenUsage?.OutputTokens),
            ("$Total", terminal.TokenUsage?.TotalTokens), ("$Category", terminal.ErrorCategory), ("$Error", terminal.ErrorText));
    }

    private static bool SameExecutionIdentity(AgentExecution left, AgentExecution right) =>
        left.Id == right.Id && left.ConversationId == right.ConversationId &&
        left.InvestigationId == right.InvestigationId && left.TaskId == right.TaskId &&
        left.AgentId == right.AgentId && left.SkillId == right.SkillId &&
        left.ProviderId == right.ProviderId && left.ModelId == right.ModelId &&
        left.StartedUtc == right.StartedUtc && left.Owner == right.Owner;

    private static void AssertNoRunningTools(SqliteConnection connection, SqliteTransaction tx, string executionId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = tx;
        command.CommandText = "SELECT COUNT(*) FROM AiAgentToolCalls WHERE AgentExecutionId=$Id AND Status='Running';";
        Add(command, "$Id", executionId);
        if (Convert.ToInt32(command.ExecuteScalar()) != 0)
            throw new InvalidOperationException("Execution still has running tool calls.");
    }

    private static void AssertToolCallCount(SqliteConnection connection, SqliteTransaction tx, AgentExecution terminal)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT COUNT(*) FROM AiAgentToolCalls WHERE AgentExecutionId=$Id;";
        Add(command, "$Id", terminal.Id);
        if (Convert.ToInt32(command.ExecuteScalar()) != terminal.ToolCallCount)
            throw new InvalidOperationException("Execution tool-call count disagrees with persisted attempts.");
    }

    private static void AssertToolOutcomeChronology(SqliteConnection connection, SqliteTransaction tx,
        AgentExecution terminal)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT StartedUtc,CompletedUtc FROM AiAgentToolCalls WHERE AgentExecutionId=$Id;";
        Add(command, "$Id", terminal.Id);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var started = ParseUtc(reader.GetString(0));
            var completed = reader.IsDBNull(1) ? null : ParseUtc(reader.GetString(1));
            if (started is null || completed is null || started < terminal.StartedUtc ||
                completed < started || completed > terminal.CompletedUtc)
                throw new InvalidOperationException("Execution completion predates a tool outcome.");
        }
    }

    private static void ValidateFinding(InvestigationFinding finding, string investigationId)
    {
        if (finding is null || string.IsNullOrWhiteSpace(finding.Id) || finding.InvestigationId != investigationId ||
            string.IsNullOrWhiteSpace(finding.CreatedByExecutionId) || string.IsNullOrWhiteSpace(finding.Title) ||
            finding.Title.Length > 240 || string.IsNullOrWhiteSpace(finding.Claim) || finding.Claim.Length > 4000 ||
            finding.Description is null || finding.Description.Length > 20_000 || !Enum.IsDefined(finding.Severity) ||
            finding.Confidence is < 0 or > 1 || double.IsNaN(finding.Confidence ?? 0) ||
            finding.VerificationStatus == FindingVerificationState.AnalystVerified || !Enum.IsDefined(finding.VerificationStatus) ||
            finding.AnalystVerifiedBy is not null || finding.AnalystVerifiedUtc is not null ||
            finding.CreatedUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Finding is invalid or claims analyst verification.");
    }

    private static void ValidateHypothesis(InvestigationHypothesis hypothesis, string investigationId)
    {
        if (hypothesis is null || string.IsNullOrWhiteSpace(hypothesis.Id) || hypothesis.InvestigationId != investigationId ||
            string.IsNullOrWhiteSpace(hypothesis.CreatedByExecutionId) || string.IsNullOrWhiteSpace(hypothesis.Statement) ||
            hypothesis.Statement.Length > 4000 || !Enum.IsDefined(hypothesis.Status) ||
            hypothesis.Confidence is < 0 or > 1 || double.IsNaN(hypothesis.Confidence ?? 0) ||
            hypothesis.CreatedUtc.Kind != DateTimeKind.Utc || hypothesis.UpdatedUtc.Kind != DateTimeKind.Utc ||
            hypothesis.UpdatedUtc < hypothesis.CreatedUtc)
            throw new ArgumentException("Hypothesis is invalid.");
    }

    private static void InsertEvidenceLink(SqliteConnection connection, SqliteTransaction tx,
        InvestigationEvidenceLink link, InvestigationEvidenceOwner expectedOwner, string expectedId,
        AgentExecution execution, CancellationToken ct, AgentToolSession? checkedSession = null)
    {
        ct.ThrowIfCancellationRequested();
        if (link is null || link.Owner != expectedOwner || link.OwnerId != expectedId ||
            !Enum.IsDefined(link.Polarity) || link.Reference is null)
            throw new ArgumentException("Evidence link has incorrect owner or polarity.");
        ValidateReference(link.Reference);
        var conversation = LoadConversationForWrite(connection, tx, execution.ConversationId) ??
            throw new InvalidOperationException("Conversation is unavailable.");
        var admitted = execution.InvestigationId is null
            ? ReferenceWithinScope(conversation.Scope, link.Reference.Identity) ||
                checkedSession?.AdmitReference(link.Reference) == true
            : InvestigationReferenceWithinScope(conversation.Scope, link.Reference.Identity);
        if (!admitted)
            throw new InvalidOperationException("Evidence is outside the conversation scope.");
        if (expectedOwner == InvestigationEvidenceOwner.ToolCall)
        {
            if (FindToolExecution(connection, tx, expectedId) != execution.Id)
                throw new InvalidOperationException("Tool evidence belongs to a different execution.");
        }
        else
        {
            var table = expectedOwner == InvestigationEvidenceOwner.Finding
                ? "AiInvestigationFindings" : "AiInvestigationHypotheses";
            if (execution.InvestigationId is null ||
                FindOwnerInvestigation(connection, tx, table, expectedId) != execution.InvestigationId)
                throw new InvalidOperationException("Evidence owner belongs to another investigation.");
        }
        InsertOrVerifyReference(connection, tx, link.Reference);
        Execute(connection, tx, $"INSERT OR IGNORE INTO {EvidenceTable(expectedOwner)}({EvidenceOwnerColumn(expectedOwner)},ReferenceId,Polarity) VALUES($Owner,$Reference,$Polarity);",
            ("$Owner", expectedId), ("$Reference", link.Reference.ReferenceId), ("$Polarity", link.Polarity.ToString()));
    }

    private static string? FindOwnerInvestigation(SqliteConnection connection, SqliteTransaction tx, string table, string id)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = $"SELECT InvestigationId FROM {table} WHERE Id=$Id;";
        Add(command, "$Id", id); return command.ExecuteScalar() as string;
    }

    private static string? FindToolExecution(SqliteConnection connection, SqliteTransaction tx, string id)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT AgentExecutionId FROM AiAgentToolCalls WHERE Id=$Id;";
        Add(command, "$Id", id); return command.ExecuteScalar() as string;
    }

    private static bool ExistsById(SqliteConnection connection, SqliteTransaction tx, string table, string id)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = $"SELECT 1 FROM {table} WHERE Id=$Id;";
        Add(command, "$Id", id); return command.ExecuteScalar() is not null;
    }

    private static void ValidatePublicationLinkOwners(InvestigationPublication publication)
    {
        var findings = publication.Findings.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        var hypotheses = publication.Hypotheses.Select(h => h.Id).ToHashSet(StringComparer.Ordinal);
        if (publication.EvidenceLinks.Any(link => link is null || link.Reference is null || (link.Owner switch
            {
                InvestigationEvidenceOwner.Finding => !findings.Contains(link.OwnerId),
                InvestigationEvidenceOwner.Hypothesis => !hypotheses.Contains(link.OwnerId),
                _ => true
            })))
            throw new ArgumentException("Publication evidence must name a published finding or hypothesis; tool evidence belongs to tool completion.");
        if (publication.EvidenceLinks.Select(link => (link.Owner, link.OwnerId,
                link.Reference.ReferenceId, link.Polarity)).Distinct().Count() != publication.EvidenceLinks.Count)
            throw new ArgumentException("Publication evidence contains duplicate links.");
    }

    // EvidenceLinks is the complete desired set for every finding and hypothesis in this publication.
    // Existing links are immutable: an update may restate them and append links, never omit one.
    private static void AssertDesiredEvidenceLinksPreserveExisting(SqliteConnection connection, SqliteTransaction tx,
        InvestigationPublication publication)
    {
        foreach (var finding in publication.Findings)
            AssertExistingLinksIncluded(connection, tx, InvestigationEvidenceOwner.Finding, finding.Id,
                publication.EvidenceLinks);
        foreach (var hypothesis in publication.Hypotheses)
            AssertExistingLinksIncluded(connection, tx, InvestigationEvidenceOwner.Hypothesis, hypothesis.Id,
                publication.EvidenceLinks);
    }

    private static void AssertExistingLinksIncluded(SqliteConnection connection, SqliteTransaction tx,
        InvestigationEvidenceOwner owner, string ownerId, IReadOnlyList<InvestigationEvidenceLink> desired)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = $"SELECT ReferenceId,Polarity FROM {EvidenceTable(owner)} WHERE {EvidenceOwnerColumn(owner)}=$Id;";
        Add(command, "$Id", ownerId);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var referenceId = reader.GetString(0);
            var polarity = Enum.Parse<InvestigationEvidencePolarity>(reader.GetString(1));
            var submitted = desired.FirstOrDefault(link => link.Owner == owner && link.OwnerId == ownerId &&
                link.Reference.ReferenceId == referenceId && link.Polarity == polarity);
            if (submitted is null)
                throw new InvalidOperationException("Publication cannot remove existing evidence links.");
        }
    }

    private static bool PublicationRetryMatches(SqliteConnection connection, SqliteTransaction tx,
        Investigation inv, AgentExecution saved, InvestigationPublication requested)
    {
        if (saved != requested.CompletedExecution || saved.InvestigationId != inv.Id ||
            inv.ConversationId != saved.ConversationId ||
            LoadMessageForWrite(connection, tx, requested.VisibleMessage!.Id) != requested.VisibleMessage ||
            inv.Status != requested.InvestigationStatus || inv.Summary != requested.Summary ||
            !inv.OpenQuestions.SequenceEqual(requested.OpenQuestions)) return false;
        if (saved.TaskId is null)
        {
            if (requested.TaskStatus is not null) return false;
        }
        else
        {
            var task = ReadTask(connection, tx, saved.TaskId);
            if (task is null || task.Status != requested.TaskStatus ||
                task.ResultSummary != requested.TaskResultSummary || task.CompletedUtc != saved.CompletedUtc)
                return false;
        }
        if (!IdsCreatedByExecutionMatch(connection, tx, "AiInvestigationTasks", "CreatedByExecutionId", saved.Id,
            requested.FollowUpTasks.Select(t => t.Id)) ||
            !IdsCreatedByExecutionMatch(connection, tx, "AiInvestigationFindings", "CreatedByExecutionId", saved.Id,
                requested.Findings.Select(f => f.Id), "AssessedByExecutionId") ||
            !IdsCreatedByExecutionMatch(connection, tx, "AiInvestigationHypotheses", "CreatedByExecutionId", saved.Id,
                requested.Hypotheses.Select(h => h.Id), "UpdatedByExecutionId")) return false;
        if (requested.FollowUpTasks.Any(t => ReadTask(connection, tx, t.Id) != t) ||
            requested.Findings.Any(f => ReadFindingById(connection, tx, f.Id) != f) ||
            requested.Hypotheses.Any(h => ReadHypothesisById(connection, tx, h.Id) != h)) return false;
        try { ValidatePublicationLinkOwners(requested); }
        catch (ArgumentException) { return false; }
        foreach (var finding in requested.Findings)
            if (!EvidenceLinksMatch(connection, tx, InvestigationEvidenceOwner.Finding, finding.Id,
                requested.EvidenceLinks.Where(link => link.Owner == InvestigationEvidenceOwner.Finding && link.OwnerId == finding.Id).ToArray()))
                return false;
        foreach (var hypothesis in requested.Hypotheses)
            if (!EvidenceLinksMatch(connection, tx, InvestigationEvidenceOwner.Hypothesis, hypothesis.Id,
                requested.EvidenceLinks.Where(link => link.Owner == InvestigationEvidenceOwner.Hypothesis && link.OwnerId == hypothesis.Id).ToArray()))
                return false;
        return true;
    }

    private static bool IdsCreatedByExecutionMatch(SqliteConnection connection, SqliteTransaction tx,
        string table, string creatorColumn, string executionId, IEnumerable<string> requestedIds,
        string? updaterColumn = null)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = updaterColumn is null
            ? $"SELECT Id FROM {table} WHERE {creatorColumn}=$Id;"
            : $"SELECT Id FROM {table} WHERE {creatorColumn}=$Id OR {updaterColumn}=$Id;";
        Add(command, "$Id", executionId);
        var savedIds = new HashSet<string>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read()) savedIds.Add(reader.GetString(0));
        return savedIds.SetEquals(requestedIds);
    }

    private static InvestigationHypothesis? ReadHypothesisById(SqliteConnection connection, SqliteTransaction tx, string id)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT * FROM AiInvestigationHypotheses WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadHypothesis(reader) : null;
    }
}
