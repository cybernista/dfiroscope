namespace ProcInsider.Models;

public class ProcessKeyLookupResult
{
    public bool IsFound { get; set; }
    public ProcessRecord? Process { get; set; }
}

public class ProcessEntityLookupResult
{
    public bool IsFound { get; set; }
    public ProcessRecord? Process { get; set; }
}
