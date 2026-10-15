using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Analysis;
using ProcInsider.Services.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    public Task<AgentExecution> StartExecutionAsync(AgentExecution execution, AiExecutionLifetime lifetime,
        CancellationToken cancellationToken = default) => Task.Run(() => NotifyAiAnnotationsChanged(StartExecution(execution, lifetime, cancellationToken, analystReentry: false)), cancellationToken);

    public Task<AgentExecution> StartCheckedExecutionAsync(AgentExecution execution, AiExecutionLifetime lifetime,
        AgentToolSession session, Func<bool> isCurrent, CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(StartExecution(execution, lifetime, cancellationToken, analystReentry: false,
            session, isCurrent)), cancellationToken);

    public Task<AgentExecution> StartCheckedExecutionWithQuestionAsync(AgentExecution execution,
        AiExecutionLifetime lifetime, AiConversationMessage question, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(StartExecution(execution, lifetime, cancellationToken, analystReentry: false,
            session, isCurrent, question)), cancellationToken);

    public Task<AgentToolCall> StartToolCallAsync(AgentToolCall toolCall, CancellationToken cancellationToken = default) =>
        Task.Run(() => StartToolCall(toolCall, cancellationToken), cancellationToken);

    public Task<AgentExecution> UpdateCheckedExecutionProgressAsync(string executionId,
        int iterationCount, ModelTokenUsage? tokenUsage, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken cancellationToken = default) =>
        Task.Run(() => UpdateCheckedExecutionProgress(executionId, iterationCount,
            tokenUsage, session, isCurrent, cancellationToken), cancellationToken);

    public Task<AgentToolCall> StartCheckedToolCallAsync(AgentToolCall toolCall,
        AgentToolSession session, Func<bool> isCurrent, CancellationToken cancellationToken = default) =>
        Task.Run(() => StartToolCall(toolCall, cancellationToken, session, isCurrent), cancellationToken);

    public Task<AgentToolCall> FinishToolCallAsync(AgentToolCall terminal,
        IReadOnlyList<InvestigationEvidenceLink> evidence, CancellationToken cancellationToken = default)
    {
        var pinned = evidence.ToArray();
        return Task.Run(() => FinishToolCall(terminal, pinned, cancellationToken), cancellationToken);
    }

    public Task<AgentToolCall> FinishCheckedToolCallAsync(AgentToolCall terminal,
        IReadOnlyList<InvestigationEvidenceLink> evidence, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken cancellationToken = default)
    {
        var pinned = evidence.ToArray();
        return Task.Run(() => FinishToolCall(terminal, pinned, cancellationToken, session, isCurrent),
            cancellationToken);
    }

    public Task<AgentExecution> FinishExecutionAsync(AgentExecution terminal, AiConversationMessage visibleMessage,
        CancellationToken cancellationToken = default) => Task.Run(() => NotifyAiAnnotationsChanged(FinishExecution(terminal, visibleMessage, cancellationToken)), cancellationToken);

    public Task<AgentExecution> FinishCheckedExecutionAsync(AgentExecution terminal,
        AiConversationMessage visibleMessage, IReadOnlyList<AiEvidenceReference> references,
        AgentToolSession session, Func<bool> isCurrent, CancellationToken cancellationToken = default)
    {
        var pinned = references.ToArray();
        return Task.Run(() => NotifyAiAnnotationsChanged(FinishExecution(terminal, visibleMessage, cancellationToken,
            session, isCurrent, pinned)), cancellationToken);
    }

    public Task<Investigation> PublishInvestigationResultAsync(InvestigationPublication publication,
        CancellationToken cancellationToken = default)
    {
        var pinned = publication with
        {
            OpenQuestions = publication.OpenQuestions.ToArray(),
            FollowUpTasks = publication.FollowUpTasks.ToArray(),
            Findings = publication.Findings.ToArray(),
            Hypotheses = publication.Hypotheses.ToArray(),
            EvidenceLinks = publication.EvidenceLinks.ToArray()
        };
        return Task.Run(() => NotifyAiAnnotationsChanged(PublishInvestigationResult(pinned, cancellationToken)), cancellationToken);
    }

    public Task<Investigation> PublishCheckedInvestigationResultAsync(InvestigationPublication publication,
        AgentToolSession session, Func<bool> isCurrent, CancellationToken cancellationToken = default)
    {
        var pinned = publication with
        {
            OpenQuestions = publication.OpenQuestions.ToArray(),
            FollowUpTasks = publication.FollowUpTasks.ToArray(),
            Findings = publication.Findings.ToArray(),
            Hypotheses = publication.Hypotheses.ToArray(),
            EvidenceLinks = publication.EvidenceLinks.ToArray()
        };
        return Task.Run(() => NotifyAiAnnotationsChanged(PublishInvestigationResult(pinned, cancellationToken, session, isCurrent)), cancellationToken);
    }

    public Task<Investigation> PublishCheckedInvestigationResultAsync(InvestigationPublication publication,
        IReadOnlyList<AiEvidenceReference> visibleReferences, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(visibleReferences);
        if (visibleReferences.Count > 50 || visibleReferences.Any(reference => reference is null) ||
            visibleReferences.Select(reference => reference.ReferenceId)
                .Distinct(StringComparer.Ordinal).Count() != visibleReferences.Count)
            throw new ArgumentException("Visible citations are invalid.", nameof(visibleReferences));
        var pinned = publication with
        {
            OpenQuestions = publication.OpenQuestions.ToArray(),
            FollowUpTasks = publication.FollowUpTasks.ToArray(),
            Findings = publication.Findings.ToArray(),
            Hypotheses = publication.Hypotheses.ToArray(),
            EvidenceLinks = publication.EvidenceLinks.ToArray()
        };
        var citations = Array.AsReadOnly(visibleReferences.ToArray());
        return Task.Run(() => NotifyAiAnnotationsChanged(PublishInvestigationResult(pinned, cancellationToken,
            session, isCurrent, citations)), cancellationToken);
    }

    public Task<InvestigationFinding> VerifyFindingByAnalystAsync(string findingId, string analystId,
        DateTime verifiedUtc, CancellationToken cancellationToken = default) =>
        Task.Run(() => VerifyFindingByAnalyst(findingId, analystId, verifiedUtc, cancellationToken), cancellationToken);

    public Task<Investigation> CloseInvestigationByAnalystAsync(string investigationId, DateTime closedUtc,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(CloseInvestigationByAnalyst(investigationId, closedUtc, cancellationToken)), cancellationToken);

    private AgentExecution StartExecution(AgentExecution requested, AiExecutionLifetime lifetime, CancellationToken ct,
        bool analystReentry, AgentToolSession? checkedSession = null, Func<bool>? isCurrent = null,
        AiConversationMessage? submittedQuestion = null)
    {
        if (lifetime is null || lifetime.IsDisposed || AiExecutionLifetime.GetOwnerState(lifetime.Owner) != AiExecutionOwnerState.Active)
            throw new InvalidOperationException("Execution requires a live local owner.");
        var execution = requested with { Owner = lifetime.Owner };
        ValidateExecution(execution, start: true);
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var existing = ReadExecution(connection, tx, execution.Id);
            if (existing is not null)
            {
                if (checkedSession is not null)
                    AssertCheckedWrite(checkedSession,
                        LoadConversationForWrite(connection, tx, existing.ConversationId), isCurrent, ct);
                if (existing != execution) throw new InvalidOperationException("Execution ID is bound to different content.");
                if (submittedQuestion is not null &&
                    LoadMessageForWrite(connection, tx, submittedQuestion.Id) != submittedQuestion)
                    throw new InvalidOperationException("Submitted question retry conflicts with committed history.");
                tx.Commit();
                return existing;
            }
            var conversation = LoadConversationForWrite(connection, tx, execution.ConversationId);
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            if (conversation is null || conversation.IsHistorical)
                throw new InvalidOperationException("Execution conversation is unavailable.");
            if (conversation.UpdatedUtc is { } conversationUpdated && execution.StartedUtc < conversationUpdated)
                throw new InvalidOperationException("Execution starts before the conversation's latest update.");
            if (execution.InvestigationId is not null)
            {
                var investigation = ReadInvestigation(connection, tx, execution.InvestigationId) ??
                    throw new InvalidOperationException("Investigation is unavailable.");
                var permittedState = analystReentry
                    ? investigation.Status is InvestigationState.NeedsEvidence or InvestigationState.NeedsHumanDecision or
                        InvestigationState.Completed or InvestigationState.Failed or InvestigationState.Cancelled
                    : investigation.Status == InvestigationState.New;
                if (investigation.ConversationId != execution.ConversationId || !permittedState ||
                    HasRunningExecution(connection, tx, investigation.Id) ||
                    execution.StartedUtc < investigation.UpdatedUtc)
                    throw new InvalidOperationException("Investigation requires explicit analyst resubmission.");
                if (execution.TaskId is not null)
                {
                    var task = ReadTask(connection, tx, execution.TaskId) ?? throw new InvalidOperationException("Task is unavailable.");
                    if (task.InvestigationId != investigation.Id || task.Status is not (InvestigationTaskState.Pending or InvestigationTaskState.NeedsEvidence or InvestigationTaskState.Failed or InvestigationTaskState.Cancelled) ||
                        execution.StartedUtc < task.CreatedUtc || execution.StartedUtc < task.CompletedUtc)
                        throw new InvalidOperationException("Task cannot start a new attempt.");
                    Execute(connection, tx, "UPDATE AiInvestigationTasks SET Status='Running',CompletedUtc=NULL,ResultSummary='' WHERE Id=$Id;", ("$Id", task.Id));
                }
                Execute(connection, tx, "UPDATE AiInvestigations SET Status='Investigating',UpdatedUtc=$Utc,CompletedUtc=NULL WHERE Id=$Id;",
                    ("$Id", investigation.Id), ("$Utc", execution.StartedUtc));
            }
            else if (execution.TaskId is not null || conversation.Scope.ContextType == AiConversationContextType.Investigation)
                throw new InvalidOperationException("Conversation-only execution cannot use investigation state.");
            if (submittedQuestion is not null)
                InsertSubmittedQuestion(connection, tx, execution, submittedQuestion);
            Execute(connection, tx, """
                INSERT INTO AiAgentExecutions(Id,ConversationId,InvestigationId,TaskId,AgentId,SkillId,ProviderId,ModelId,
                    StartedUtc,CompletedUtc,Status,IterationCount,ToolCallCount,InputTokens,OutputTokens,TotalTokens,
                    RuntimeLifetimeId,OwnerMachineFingerprint,OwnerWindowsSessionId,ErrorCategory,ErrorText,OriginalQuestionId)
                VALUES($Id,$Conversation,$Investigation,$Task,$Agent,$Skill,$Provider,$Model,$Started,NULL,'Running',
                    $Iterations,$Calls,NULL,NULL,NULL,$Lifetime,$Machine,$Session,$Category,$Error,$Question);
                """, ("$Id", execution.Id), ("$Conversation", execution.ConversationId), ("$Investigation", execution.InvestigationId),
                ("$Task", execution.TaskId), ("$Agent", execution.AgentId), ("$Skill", execution.SkillId),
                ("$Provider", execution.ProviderId), ("$Model", execution.ModelId), ("$Started", execution.StartedUtc),
                ("$Iterations", execution.IterationCount), ("$Calls", execution.ToolCallCount),
                ("$Lifetime", execution.Owner!.LifetimeId), ("$Machine", execution.Owner.MachineFingerprint),
                ("$Session", execution.Owner.WindowsSessionId), ("$Category", execution.ErrorCategory), ("$Error", execution.ErrorText),
                ("$Question", submittedQuestion?.Id));
            ct.ThrowIfCancellationRequested();
            if (lifetime.IsDisposed) throw new InvalidOperationException("Execution owner expired before commit.");
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            tx.Commit();
            return execution;
        }
    }

    private AgentToolCall StartToolCall(AgentToolCall tool, CancellationToken ct,
        AgentToolSession? checkedSession = null, Func<bool>? isCurrent = null)
    {
        ValidateTool(tool, start: true);
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var existing = ReadToolCall(connection, tx, tool.Id);
            if (existing is not null)
            {
                if (checkedSession is not null)
                {
                    var existingExecution = ReadExecution(connection, tx, existing.AgentExecutionId) ??
                        throw new InvalidOperationException("Execution is unavailable.");
                    AssertCheckedWrite(checkedSession,
                        LoadConversationForWrite(connection, tx, existingExecution.ConversationId),
                        isCurrent, ct);
                }
                if (existing != tool) throw new InvalidOperationException("Tool call ID is bound to different content.");
                tx.Commit();
                return existing;
            }
            var execution = ReadExecution(connection, tx, tool.AgentExecutionId) ?? throw new InvalidOperationException("Execution is unavailable.");
            var conversation = checkedSession is null ? null :
                LoadConversationForWrite(connection, tx, execution.ConversationId);
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            if (execution.Status != AgentExecutionState.Running ||
                AiExecutionLifetime.GetOwnerState(execution.Owner) != AiExecutionOwnerState.Active ||
                tool.StartedUtc < execution.StartedUtc ||
                tool.CompletedUtc < execution.StartedUtc)
                throw new InvalidOperationException("Tool call requires an active execution.");
            Execute(connection, tx, """
                INSERT INTO AiAgentToolCalls(Id,AgentExecutionId,ToolName,StartedUtc,CompletedUtc,Status,
                    InputSummary,ResultSummary,ErrorCategory,ErrorText)
                VALUES($Id,$Execution,$Name,$Started,$Completed,$Status,$Input,$Result,$Category,$Error);
                """, ("$Id", tool.Id), ("$Execution", tool.AgentExecutionId), ("$Name", tool.ToolName),
                ("$Started", tool.StartedUtc), ("$Completed", tool.CompletedUtc), ("$Status", tool.Status.ToString()),
                ("$Input", tool.InputSummary), ("$Result", tool.ResultSummary),
                ("$Category", tool.ErrorCategory), ("$Error", tool.ErrorText));
            ct.ThrowIfCancellationRequested();
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            tx.Commit(); return tool;
        }
    }

    private AgentExecution UpdateCheckedExecutionProgress(string executionId, int iterationCount,
        ModelTokenUsage? usage, AgentToolSession session, Func<bool> isCurrent, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(executionId) || session is null || isCurrent is null ||
            iterationCount < 0 || iterationCount > session.AttemptedIterations ||
            iterationCount > session.Definition.Limits.MaximumIterations ||
            usage?.InputTokens is < 0 || usage?.OutputTokens is < 0 || usage?.TotalTokens is < 0)
            throw new ArgumentException("Execution progress is invalid.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var current = ReadExecution(connection, tx, executionId) ??
                throw new InvalidOperationException("Execution is unavailable.");
            var conversation = LoadConversationForWrite(connection, tx, current.ConversationId);
            AssertCheckedWrite(session, conversation, isCurrent, ct);
            if (current.Status != AgentExecutionState.Running ||
                current.AgentId != session.AgentId || current.SkillId != session.SkillId ||
                AiExecutionLifetime.GetOwnerState(current.Owner) != AiExecutionOwnerState.Active ||
                iterationCount < current.IterationCount ||
                !UsageIsMonotonic(current.TokenUsage, usage))
                throw new InvalidOperationException("Execution progress is stale or conflicts with its owner.");
            using var count = connection.CreateCommand();
            count.Transaction = tx;
            count.CommandText = "SELECT COUNT(*) FROM AiAgentToolCalls WHERE AgentExecutionId=$Id;";
            Add(count, "$Id", executionId);
            var actualCalls = Convert.ToInt32(count.ExecuteScalar());
            if (actualCalls < current.ToolCallCount || actualCalls > session.Definition.Limits.MaximumToolCalls)
                throw new InvalidOperationException("Execution Tool count conflicts with durable attempts.");
            Execute(connection, tx, """
                UPDATE AiAgentExecutions SET IterationCount=$Iterations,ToolCallCount=$Calls,
                    InputTokens=$Input,OutputTokens=$Output,TotalTokens=$Total
                WHERE Id=$Id AND Status='Running';
                """, ("$Id", executionId), ("$Iterations", iterationCount), ("$Calls", actualCalls),
                ("$Input", usage?.InputTokens), ("$Output", usage?.OutputTokens),
                ("$Total", usage?.TotalTokens));
            ct.ThrowIfCancellationRequested();
            AssertCheckedWrite(session, conversation, isCurrent, ct);
            tx.Commit();
            return current with
            {
                IterationCount = iterationCount, ToolCallCount = actualCalls, TokenUsage = usage
            };
        }
    }

    private static bool UsageIsMonotonic(ModelTokenUsage? prior, ModelTokenUsage? next) =>
        prior is null || next is null ||
        (prior.InputTokens is null || next.InputTokens is null ||
            next.InputTokens >= prior.InputTokens) &&
        (prior.OutputTokens is null || next.OutputTokens is null ||
            next.OutputTokens >= prior.OutputTokens) &&
        (prior.TotalTokens is null || next.TotalTokens is null ||
            next.TotalTokens >= prior.TotalTokens);

    private AgentToolCall FinishToolCall(AgentToolCall terminal, IReadOnlyList<InvestigationEvidenceLink> evidence,
        CancellationToken ct, AgentToolSession? checkedSession = null, Func<bool>? isCurrent = null)
    {
        ValidateTool(terminal, start: false);
        if (terminal.Status == AgentToolCallState.Running || evidence.Count > 50 ||
            terminal.Status == AgentToolCallState.Denied && evidence.Count > 0)
            throw new ArgumentException("Tool call must have a terminal result.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var current = ReadToolCall(connection, tx, terminal.Id) ?? throw new InvalidOperationException("Tool call is unavailable.");
            var execution = ReadExecution(connection, tx, current.AgentExecutionId) ?? throw new InvalidOperationException("Execution is unavailable.");
            var conversation = checkedSession is null ? null :
                LoadConversationForWrite(connection, tx, execution.ConversationId);
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            if (current.Status != AgentToolCallState.Running)
            {
                if (current != terminal || !EvidenceLinksMatch(connection, tx, InvestigationEvidenceOwner.ToolCall,
                    terminal.Id, evidence))
                    throw new InvalidOperationException("Tool result retry conflicts with committed audit.");
                tx.Commit(); return current;
            }
            if (execution.Status != AgentExecutionState.Running || current.Status != AgentToolCallState.Running ||
                AiExecutionLifetime.GetOwnerState(execution.Owner) != AiExecutionOwnerState.Active ||
                current.AgentExecutionId != terminal.AgentExecutionId || current.ToolName != terminal.ToolName ||
                current.StartedUtc != terminal.StartedUtc || current.InputSummary != terminal.InputSummary ||
                terminal.CompletedUtc < execution.StartedUtc)
                throw new InvalidOperationException("Tool call cannot transition.");
            foreach (var link in evidence)
                InsertEvidenceLink(connection, tx, link, InvestigationEvidenceOwner.ToolCall, terminal.Id,
                    execution, ct, checkedSession);
            Execute(connection, tx, """
                UPDATE AiAgentToolCalls SET Status=$Status,CompletedUtc=$Completed,ResultSummary=$Result,
                    ErrorCategory=$Category,ErrorText=$Error WHERE Id=$Id AND Status='Running';
                """, ("$Id", terminal.Id), ("$Status", terminal.Status.ToString()),
                ("$Completed", terminal.CompletedUtc), ("$Result", terminal.ResultSummary),
                ("$Category", terminal.ErrorCategory), ("$Error", terminal.ErrorText));
            ct.ThrowIfCancellationRequested();
            if (checkedSession is not null)
                AssertCheckedWrite(checkedSession, conversation, isCurrent, ct);
            tx.Commit(); return terminal;
        }
    }

    private static void AssertCheckedWrite(AgentToolSession session, AiConversation? conversation,
        Func<bool>? isCurrent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        bool current;
        try { current = isCurrent?.Invoke() == true; }
        catch (Exception) { current = false; }
        if (!current || conversation is null || conversation.IsHistorical ||
            conversation.Scope.ScopeKey != session.Scope.ScopeKey ||
            conversation.Scope.ContextType == AiConversationContextType.Object &&
                (session.Target is null || conversation.Scope.ObjectReference?.CanonicalObjectKey != session.Target.CanonicalObjectKey) ||
            !session.OwnerPolicy.CheckIteration(session))
            throw new InvalidOperationException("Checked AI write lost its captured scope or generation.");
    }

    private static void InsertSubmittedQuestion(SqliteConnection connection, SqliteTransaction tx,
        AgentExecution execution, AiConversationMessage question)
    {
        if (string.IsNullOrWhiteSpace(question.Id) || question.ConversationId != execution.ConversationId ||
            !string.Equals(question.Role, "user", StringComparison.OrdinalIgnoreCase) ||
            question.Status != "Succeeded" || question.TimestampUtc != execution.StartedUtc ||
            string.IsNullOrWhiteSpace(question.Content) || question.Content.Length > 100_000 ||
            question.ErrorText.Length != 0 || question.IsHistorical ||
            question.OriginalProviderKind is not null || question.OriginalBaseUrl is not null ||
            question.OriginalCreatedUtc is not null || question.OriginalProviderName is not null ||
            question.OriginalModelName is not null || question.OriginalErrorText is not null ||
            LoadMessageForWrite(connection, tx, question.Id) is not null)
            throw new ArgumentException("Submitted analyst question is invalid or already used.");
        Execute(connection, tx, """
            INSERT INTO AiMessages(Id,ConversationId,Role,Content,TimestampUtc,ProviderId,ModelId,Status,ErrorText)
            VALUES($Id,$Conversation,$Role,$Content,$Utc,$Provider,$Model,'Succeeded','');
            """, ("$Id", question.Id), ("$Conversation", question.ConversationId),
            ("$Role", question.Role), ("$Content", question.Content), ("$Utc", question.TimestampUtc),
            ("$Provider", question.ProviderId), ("$Model", question.ModelId));
        Execute(connection, tx,
            "UPDATE AiConversations SET UpdatedUtc=CASE WHEN UpdatedUtc<$Utc THEN $Utc ELSE UpdatedUtc END WHERE Id=$Id;",
            ("$Utc", question.TimestampUtc), ("$Id", question.ConversationId));
    }

    private static void Execute(SqliteConnection connection, SqliteTransaction tx, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = tx;
        command.CommandText = sql;
        foreach (var parameter in parameters) Add(command, parameter.Name, parameter.Value);
        command.ExecuteNonQuery();
    }

    private static bool EvidenceLinksMatch(SqliteConnection connection, SqliteTransaction tx,
        InvestigationEvidenceOwner owner, string ownerId, IReadOnlyList<InvestigationEvidenceLink> submitted)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = $"SELECT ReferenceId,Polarity FROM {EvidenceTable(owner)} WHERE {EvidenceOwnerColumn(owner)}=$Id;";
        Add(command, "$Id", ownerId);
        var saved = new HashSet<(string, string)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read()) saved.Add((reader.GetString(0), reader.GetString(1)));
        if (submitted.Any(link => link.Owner != owner || link.OwnerId != ownerId ||
            link.Reference is null || !Enum.IsDefined(link.Polarity)) ||
            !saved.SetEquals(submitted.Select(link => (link.Reference.ReferenceId, link.Polarity.ToString()))))
            return false;
        return submitted.All(link =>
            LoadReference(connection, tx, link.Reference.ReferenceId) == link.Reference);
    }

    private static void ValidateExecution(AgentExecution execution, bool start)
    {
        if (execution is null || string.IsNullOrWhiteSpace(execution.Id) || string.IsNullOrWhiteSpace(execution.ConversationId) ||
            string.IsNullOrWhiteSpace(execution.AgentId) || string.IsNullOrWhiteSpace(execution.SkillId) ||
            string.IsNullOrWhiteSpace(execution.ProviderId) || string.IsNullOrWhiteSpace(execution.ModelId) ||
            execution.Id.Length > 160 || execution.AgentId.Length > 120 || execution.SkillId.Length > 120 ||
            execution.StartedUtc.Kind != DateTimeKind.Utc || execution.CompletedUtc is { Kind: not DateTimeKind.Utc } ||
            execution.CompletedUtc < execution.StartedUtc || !Enum.IsDefined(execution.Status) ||
            execution.IterationCount is < 0 or > 10_000 || execution.ToolCallCount is < 0 or > 10_000 ||
            execution.ErrorCategory.Length > 120 || execution.ErrorText.Length > ModelDiagnosticRedactor.MaximumDiagnosticCharacters ||
            execution.Owner is null || string.IsNullOrWhiteSpace(execution.Owner.LifetimeId) ||
            string.IsNullOrWhiteSpace(execution.Owner.MachineFingerprint) || execution.Owner.WindowsSessionId < 0 ||
            execution.TokenUsage?.InputTokens is < 0 || execution.TokenUsage?.OutputTokens is < 0 ||
            execution.TokenUsage?.TotalTokens is < 0)
            throw new ArgumentException("Agent execution is invalid.");
        if (start && (execution.Status != AgentExecutionState.Running || execution.CompletedUtc is not null ||
            execution.TokenUsage is not null || execution.IterationCount != 0 || execution.ToolCallCount != 0 ||
            execution.ErrorCategory.Length != 0 || execution.ErrorText.Length != 0))
            throw new ArgumentException("New execution must start without a result.");
        if (!start && (execution.Status == AgentExecutionState.Running || execution.CompletedUtc is null))
            throw new ArgumentException("Execution needs a terminal result and time.");
    }

    private static void ValidateTool(AgentToolCall tool, bool start)
    {
        if (tool is null || string.IsNullOrWhiteSpace(tool.Id) || string.IsNullOrWhiteSpace(tool.AgentExecutionId) ||
            string.IsNullOrWhiteSpace(tool.ToolName) || tool.ToolName.Length > 160 ||
            tool.StartedUtc.Kind != DateTimeKind.Utc || tool.CompletedUtc is { Kind: not DateTimeKind.Utc } ||
            tool.CompletedUtc < tool.StartedUtc || !Enum.IsDefined(tool.Status) ||
            tool.InputSummary.Length > 4000 || tool.ResultSummary.Length > 4000 ||
            tool.ErrorCategory.Length > 120 || tool.ErrorText.Length > 4000)
            throw new ArgumentException("Tool call is invalid.");
        if (start && tool.Status == AgentToolCallState.Running &&
            (tool.CompletedUtc is not null || tool.ResultSummary.Length != 0 || tool.ErrorCategory.Length != 0 || tool.ErrorText.Length != 0))
            throw new ArgumentException("Running tool call cannot already have a result.");
        if (start && tool.Status != AgentToolCallState.Running && tool.Status != AgentToolCallState.Denied)
            throw new ArgumentException("Tool call must start Running or Denied.");
        if (tool.Status == AgentToolCallState.Denied && tool.CompletedUtc is null)
            throw new ArgumentException("Denied tool call requires a time.");
        if (!start && tool.CompletedUtc is null) throw new ArgumentException("Terminal tool call requires a time.");
    }
}
