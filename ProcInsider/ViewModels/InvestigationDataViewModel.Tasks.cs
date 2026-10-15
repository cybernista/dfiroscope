using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;

namespace ProcInsider.ViewModels;

public partial class InvestigationDataViewModel
{
    private bool CanRunFollowUpTask(InvestigationTask? task) =>
        !IsBusy && _mutationDepth == 0 && Current(_revision, _selectedGeneration) &&
        Investigation?.Target is not null &&
        Investigation.Status is not (InvestigationState.Closed or InvestigationState.Investigating) &&
        task is not null && task.InvestigationId == Investigation.Id &&
        (task.Status is InvestigationTaskState.Pending or InvestigationTaskState.NeedsEvidence or
            InvestigationTaskState.Failed or InvestigationTaskState.Cancelled) &&
        Tasks.Any(saved => saved == task) &&
        Messages.Any(message => message.InvestigationTasks.Any(saved => saved == task));

    [RelayCommand(CanExecute = nameof(CanRunFollowUpTask))]
    private Task RunFollowUpTaskAsync(InvestigationTask? task)
    {
        // Recheck inside the command too: stale/recycled controls cannot submit another task.
        if (!CanRunFollowUpTask(task)) return Task.CompletedTask;
        RefreshProviderDisclosure();
        return BeginExecutionAsync(task!.Objective, task.Id);
    }

    private static Dictionary<string, InvestigationTask[]> ProjectTaskActions(Investigation saved,
        IReadOnlyList<AiConversationMessage> messages, IReadOnlyList<AgentExecution> executions,
        IReadOnlyList<InvestigationTask> tasks)
    {
        var result = new Dictionary<string, InvestigationTask[]>(StringComparer.Ordinal);
        var completed = executions.Where(execution => execution.InvestigationId == saved.Id &&
            execution.ConversationId == saved.ConversationId &&
            execution.Status == AgentExecutionState.Completed && execution.CompletedUtc is not null).ToArray();
        bool Matches(AiConversationMessage message, AgentExecution execution) =>
            !message.IsHistorical && message.ConversationId == saved.ConversationId &&
            message.Role.Equals("assistant", StringComparison.OrdinalIgnoreCase) &&
            message.Status.Equals("Succeeded", StringComparison.OrdinalIgnoreCase) &&
            message.ProviderId == execution.ProviderId && message.ModelId == execution.ModelId &&
            message.TimestampUtc >= execution.StartedUtc && message.TimestampUtc <= execution.CompletedUtc;
        foreach (var execution in completed)
        {
            // Runtime now uses the execution ID for its immutable result message: an exact
            // durable link without changing the annotation schema. Never infer task authority from prose.
            var exact = messages.Where(message => message.Id == execution.Id).ToArray();
            AiConversationMessage? answer = exact.Length == 1 && Matches(exact[0], execution) ? exact[0] : null;
            if (exact.Length == 0)
            {
                // Older Runtime answers have random IDs. Recover only a unique association in
                // both directions using the existing transaction's validated time/provider bounds.
                var candidates = messages.Where(message => Matches(message, execution)).ToArray();
                if (candidates.Length == 1 && completed.Count(other => Matches(candidates[0], other)) == 1)
                    answer = candidates[0];
            }
            if (answer is null) continue;
            var proposed = tasks.Where(task => task.InvestigationId == saved.Id &&
                task.CreatedByExecutionId == execution.Id).ToArray();
            if (proposed.Length > 0) result[answer.Id] = proposed;
        }
        return result;
    }
}
