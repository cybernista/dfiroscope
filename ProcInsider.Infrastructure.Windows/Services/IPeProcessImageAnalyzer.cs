using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public interface IPeProcessImageAnalyzer
{
    Task<PeAnalysisRecord> AnalyzeProcessImageAsync(
        ProcessInfo process,
        PeStringExtractionMode stringExtractionMode,
        CancellationToken cancellationToken = default);

    PeAnalysisRecord CreateProcessImageRecordFromTemplate(
        ProcessInfo process,
        PeAnalysisRecord template);
}
