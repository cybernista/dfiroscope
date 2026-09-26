using System.Collections.ObjectModel;
using System.Globalization;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public sealed class ProcessRiskSourceCoverageRowViewModel
{
    public ProcessRiskSourceCoverageRowViewModel(
        string source,
        string availability,
        string confidence,
        string findings,
        string signals,
        string diagnostic)
    {
        Source = source;
        Availability = availability;
        Confidence = confidence;
        Findings = findings;
        Signals = signals;
        Diagnostic = diagnostic;
    }

    public string Source { get; }
    public string Availability { get; }
    public string Confidence { get; }
    public string Findings { get; }
    public string Signals { get; }
    public string Diagnostic { get; }
}

public sealed class ProcessRiskContributorRowViewModel
{
    public ProcessRiskContributorRowViewModel(
        int order,
        string source,
        string severity,
        string scoreDelta,
        string confidence,
        string summary,
        string evidenceReferences)
    {
        Order = order;
        Source = source;
        Severity = severity;
        ScoreDelta = scoreDelta;
        Confidence = confidence;
        Summary = summary;
        EvidenceReferences = evidenceReferences;
    }

    public int Order { get; }
    public string Source { get; }
    public string Severity { get; }
    public string ScoreDelta { get; }
    public string Confidence { get; }
    public string Summary { get; }
    public string EvidenceReferences { get; }
}

/// <summary>
/// Presentation-only selected-process Process Risk Score state. SQLite access and
/// compatibility decisions remain in IProcessRiskProjectionQueryService.
/// </summary>
public sealed class ProcessRiskDetailsViewModel : ViewModelBase
{
    private const int MaximumContributors = 512;
    private long _loadGeneration;
    private string _headerText = "No process selected";
    private string _statusText = "Select a process to inspect its Process Risk Score.";
    private string _diagnosticText = string.Empty;
    private bool _hasSelection;
    private bool _isLoading;

    public ObservableCollection<PropertyItemViewModel> SummaryProperties { get; } = [];
    public ObservableCollection<ProcessRiskSourceCoverageRowViewModel> Sources { get; } = [];
    public ObservableCollection<ProcessRiskContributorRowViewModel> Contributors { get; } = [];

    public string HeaderText
    {
        get => _headerText;
        private set => SetProperty(ref _headerText, value);
    }

    public string StatusText
    {
        get => _statusText;
        private set => SetProperty(ref _statusText, value);
    }

    public string DiagnosticText
    {
        get => _diagnosticText;
        private set => SetProperty(ref _diagnosticText, value);
    }

    public bool HasSelection
    {
        get => _hasSelection;
        private set => SetProperty(ref _hasSelection, value);
    }

    public bool IsLoading
    {
        get => _isLoading;
        private set => SetProperty(ref _isLoading, value);
    }

    public bool HasContributors => Contributors.Count > 0;

    public async Task LoadAsync(
        IProcessRiskProjectionQueryService? queries,
        string processEntityId,
        string processKey,
        string processDisplay,
        CancellationToken cancellationToken)
    {
        var generation = Interlocked.Increment(ref _loadGeneration);
        if (string.IsNullOrWhiteSpace(processEntityId) &&
            string.IsNullOrWhiteSpace(processKey))
        {
            Clear("Select a process to inspect its Process Risk Score.");
            return;
        }

        HeaderText = string.IsNullOrWhiteSpace(processDisplay)
            ? "Process Risk Score"
            : $"Process Risk Score — {processDisplay}";
        HasSelection = true;
        IsLoading = true;
        StatusText = "Loading the persisted process-risk explanation...";
        DiagnosticText = string.Empty;
        SummaryProperties.Clear();
        Sources.Clear();
        Contributors.Clear();
        OnPropertyChanged(nameof(HasContributors));

        if (queries == null)
        {
            ApplyUnavailable(
                generation,
                ProcessRiskProjectionReadState.NotReady,
                "The active workspace has no process-risk query projection.",
                processEntityId,
                processKey);
            return;
        }

        ProcessRiskProjectionDetailsRecord details;
        try
        {
            details = await Task.Run(
                () => queries.GetCurrentDetails(
                    processEntityId,
                    processKey,
                    MaximumContributors,
                    cancellationToken),
                cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            ApplyUnavailable(
                generation,
                ProcessRiskProjectionReadState.Failed,
                $"The persisted process-risk explanation could not be read: {ex.Message}",
                processEntityId,
                processKey);
            return;
        }

        if (generation != Volatile.Read(ref _loadGeneration))
        {
            return;
        }

        ApplyDetails(details);
    }

    public void Clear(string message = "Select a process to inspect its Process Risk Score.")
    {
        Interlocked.Increment(ref _loadGeneration);
        HeaderText = "No process selected";
        StatusText = message;
        DiagnosticText = string.Empty;
        HasSelection = false;
        IsLoading = false;
        SummaryProperties.Clear();
        Sources.Clear();
        Contributors.Clear();
        OnPropertyChanged(nameof(HasContributors));
    }

    private void ApplyDetails(ProcessRiskProjectionDetailsRecord details)
    {
        var current = details.Current;
        IsLoading = false;
        StatusText = FormatReadState(current);
        DiagnosticText = current.Diagnostic;
        SummaryProperties.Clear();
        Sources.Clear();
        Contributors.Clear();

        AddSummary("Identity", "Process Entity ID", ValueOrUnavailable(current.ProcessEntityId));
        AddSummary("Identity", "Process Key", ValueOrUnavailable(current.ProcessKey));
        AddSummary("Projection", "Read State", current.ReadState.ToString());

        if (current.ReadState != ProcessRiskProjectionReadState.Available ||
            current.Projection == null)
        {
            AddCanonicalUnavailableSources(current.ReadState, current.Diagnostic);
            OnPropertyChanged(nameof(HasContributors));
            return;
        }

        var projection = current.Projection;
        AddSummary(
            "Projection",
            "Score",
            projection.Score?.ToString(CultureInfo.InvariantCulture) ?? "Not projected (Unknown)");
        AddSummary("Projection", "Band", projection.Band.ToString());
        AddSummary("Projection", "Projection State", projection.State.ToString());
        AddSummary("Projection", "Confidence", projection.Confidence.ToString("P0", CultureInfo.InvariantCulture));
        AddSummary("Projection", "Coverage", projection.Coverage.ToString("P0", CultureInfo.InvariantCulture));
        AddSummary("Projection", "Projected UTC", projection.ProjectedUtc.ToString("O", CultureInfo.InvariantCulture));
        AddSummary("Versions", "Mapper", $"{current.MapperId} {current.MapperVersion}".Trim());
        AddSummary("Versions", "Policy", $"{projection.PolicyId} {projection.PolicyVersion}".Trim());
        AddSummary("Versions", "Aggregation", current.AggregationVersion);
        AddSummary("Input", "Evaluation ID", ValueOrUnavailable(current.EvaluationId));
        AddSummary("Input", "Input Identity Hash", ValueOrUnavailable(current.InputIdentityHash));
        AddSummary("Input", "Process Observation", ValueOrUnavailable(current.ObservationId));
        AddSummary("Input", "PE Analysis", ValueOrUnavailable(current.PeAnalysisId));
        AddSummary("Input", "Authenticode Verification", ValueOrUnavailable(current.AuthenticodeVerificationId));

        foreach (var source in current.Sources.OrderBy(source => source.SourceKind))
        {
            Sources.Add(new ProcessRiskSourceCoverageRowViewModel(
                source.SourceKind.ToString(),
                source.Availability.ToString(),
                source.Confidence.ToString("P0", CultureInfo.InvariantCulture),
                source.FindingCount.ToString(CultureInfo.InvariantCulture),
                source.SignalCount.ToString(CultureInfo.InvariantCulture),
                source.Diagnostic));
        }

        for (var index = 0; index < details.Contributors.Count; index++)
        {
            var contribution = details.Contributors[index];
            Contributors.Add(new ProcessRiskContributorRowViewModel(
                index + 1,
                contribution.SourceKind.ToString(),
                contribution.Signal.Severity.ToString(),
                contribution.Signal.ScoreDelta.ToString("+0;-0;0", CultureInfo.InvariantCulture),
                contribution.Signal.Confidence.ToString("P0", CultureInfo.InvariantCulture),
                contribution.Finding.Summary,
                string.Join(
                    "; ",
                    contribution.Signal.EvidenceReferences.Select(reference =>
                        $"{reference.Kind}:{reference.Id}"))));
        }

        OnPropertyChanged(nameof(HasContributors));
    }

    private void ApplyUnavailable(
        long generation,
        ProcessRiskProjectionReadState state,
        string diagnostic,
        string processEntityId,
        string processKey)
    {
        if (generation != Volatile.Read(ref _loadGeneration))
        {
            return;
        }

        ApplyDetails(new ProcessRiskProjectionDetailsRecord
        {
            Current = new ProcessRiskProjectionRecord
            {
                ReadState = state,
                Diagnostic = diagnostic,
                ProcessEntityId = processEntityId?.Trim() ?? string.Empty,
                ProcessKey = processKey?.Trim() ?? string.Empty
            }
        });
    }

    private void AddCanonicalUnavailableSources(
        ProcessRiskProjectionReadState state,
        string diagnostic)
    {
        foreach (var source in ProcessRiskAggregationPolicy.LocalFirstVersion1.Sources
                     .OrderBy(source => source.SourceKind))
        {
            Sources.Add(new ProcessRiskSourceCoverageRowViewModel(
                source.SourceKind.ToString(),
                $"Projection {state}",
                "—",
                "—",
                "—",
                diagnostic));
        }
    }

    private void AddSummary(string group, string name, string value) =>
        SummaryProperties.Add(new PropertyItemViewModel(group, name, value));

    private static string FormatReadState(ProcessRiskProjectionRecord current) =>
        current.ReadState switch
        {
            ProcessRiskProjectionReadState.Available when current.Projection?.Score is int score =>
                $"Evaluated score {score.ToString(CultureInfo.InvariantCulture)} in the {current.Projection.Band} triage band.",
            ProcessRiskProjectionReadState.Available =>
                "Evaluation completed with Unknown state; no numeric score was projected.",
            ProcessRiskProjectionReadState.Unsupported =>
                "Process Risk Score is unsupported by this capture revision.",
            ProcessRiskProjectionReadState.Stale =>
                "The persisted Process Risk Score is stale and is not displayed.",
            ProcessRiskProjectionReadState.Failed =>
                "The persisted Process Risk Score failed validation and is not displayed.",
            ProcessRiskProjectionReadState.AmbiguousLegacyKey =>
                "The legacy process identity is ambiguous; no Process Risk Score was selected.",
            _ => "The Process Risk Score is not ready for this exact process entity."
        };

    private static string ValueOrUnavailable(string value) =>
        string.IsNullOrWhiteSpace(value) ? "<not available>" : value;
}
