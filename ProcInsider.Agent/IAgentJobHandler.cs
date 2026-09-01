namespace ProcInsider.Agent;

internal interface IAgentJobHandler
{
    Task ExecuteAsync(AgentJobContext context);
}
