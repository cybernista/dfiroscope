using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class SigmaViewModel : ViewModelBase
{
    private const int DefaultMaxFindings = 1000;
    private static readonly HashSet<string> RuleExtensions = new(StringComparer.OrdinalIgnoreCase) { ".yml", ".yaml" };

    private readonly TelemetryProjectionService _projectionService;
    private readonly SigmaRuleParser _ruleParser;
    private readonly Action<TelemetrySearchResult> _navigateToResult;
    private readonly FeatureAccessService _featureAccess;
    private readonly SigmaRiskProjectionUpdateService? _riskProjectionUpdateService;
    private List<SigmaRule> _rules = new();
    private List<SigmaRuleDiagnostic> _importDiagnostics = new();

    [ObservableProperty]
    private string rulePath = string.Empty;

    [ObservableProperty]
    private string ruleSummary = "Import a Sigma YAML rule to run against staged telemetry.";

    [ObservableProperty]
    private bool isRunning;

    [ObservableProperty]
    private string statusMessage = "Import a Sigma YAML rule to run against staged telemetry.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFindings))]
    [NotifyPropertyChangedFor(nameof(IsEmpty))]
    private ObservableCollection<SigmaFinding> findings = new();

    [ObservableProperty]
    private ICollectionView? findingsView;

    [ObservableProperty]
    private SigmaFinding? selectedFinding;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRuleDiagnostics))]
    private ObservableCollection<SigmaRuleDiagnostic> ruleDiagnostics = new();

    public bool HasRule => _rules.Count > 0;
    public bool HasFindings => Findings.Count > 0;
    public bool IsEmpty => !IsRunning && Findings.Count == 0;
    public bool HasRuleDiagnostics => RuleDiagnostics.Count > 0;

    public event EventHandler<SigmaRiskProjectionUpdateResult>? RiskProjectionUpdated;

    public SigmaViewModel(
        TelemetryProjectionService projectionService,
        SigmaRuleParser ruleParser,
        Action<TelemetrySearchResult> navigateToResult,
        FeatureAccessService? featureAccess = null,
        SigmaRiskProjectionUpdateService? riskProjectionUpdateService = null)
    {
        _projectionService = projectionService;
        _ruleParser = ruleParser;
        _navigateToResult = navigateToResult;
        _featureAccess = featureAccess ?? new FeatureAccessService(CurrentEducationalReleaseProfile.RuntimeCatalog);
        _riskProjectionUpdateService = riskProjectionUpdateService;
        RebuildFindingsView();
    }

    [RelayCommand(CanExecute = nameof(CanStartOperation))]
    public async Task ImportRuleAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Import Sigma Rule",
            DefaultExt = ".yml",
            Filter = "Sigma rules (*.yml;*.yaml)|*.yml;*.yaml|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Sigma rule import canceled.";
            return;
        }

        IsRunning = true;
        StatusMessage = "Importing Sigma rule...";
        try
        {
            var path = dialog.FileName;
            var result = await Task.Run(() => LoadRulesFromFiles(new[] { path }, path));
            ApplyRuleLoadResult(result);
        }
        catch (Exception ex)
        {
            ResetLoadedRules("Import failed.", $"Failed to import Sigma rule: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
            OnPropertyChanged(nameof(HasRule));
            OnPropertyChanged(nameof(IsEmpty));
            RunRuleCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanStartOperation))]
    public async Task ImportRuleFolderAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = "Import Sigma Rule Folder",
            Multiselect = false
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Sigma folder import canceled.";
            return;
        }

        IsRunning = true;
        StatusMessage = "Importing Sigma rule folder...";
        try
        {
            var folderPath = dialog.FolderName;
            var result = await Task.Run(() =>
            {
                var diagnostics = new List<SigmaRuleDiagnostic>();
                var files = EnumerateRuleFiles(folderPath, diagnostics);
                return LoadRulesFromFiles(files, folderPath, diagnostics);
            });
            ApplyRuleLoadResult(result);
        }
        catch (Exception ex)
        {
            ResetLoadedRules("Folder import failed.", $"Failed to import Sigma rule folder: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
            OnPropertyChanged(nameof(HasRule));
            OnPropertyChanged(nameof(IsEmpty));
            ImportRuleCommand.NotifyCanExecuteChanged();
            ImportRuleFolderCommand.NotifyCanExecuteChanged();
            RunRuleCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanRunRule))]
    public async Task RunRuleAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (_rules.Count == 0)
        {
            StatusMessage = "Import a Sigma rule before running detection.";
            return;
        }

        IsRunning = true;
        StatusMessage = "Running Sigma rule against staged telemetry...";
        try
        {
            var rules = _rules.ToList();
            var result = await Task.Run(() =>
            {
                return _projectionService.RunSigmaRulesWithDiagnostics(rules, DefaultMaxFindings);
            });
            var riskUpdate = _riskProjectionUpdateService == null
                ? null
                : await Task.Run(() => _riskProjectionUpdateService.Update(
                    rules,
                    result,
                    DateTime.UtcNow));

            Findings = new ObservableCollection<SigmaFinding>(result.Findings);
            RebuildFindingsView();
            SelectedFinding = null;
            SetRuleDiagnostics(_importDiagnostics.Concat(result.Diagnostics));
            OnPropertyChanged(nameof(HasFindings));
            OnPropertyChanged(nameof(IsEmpty));
            var diagnosticSuffix = RuleDiagnostics.Count > 0
                ? $" {RuleDiagnostics.Count} rule diagnostic(s)."
                : string.Empty;
            var compatibilitySuffix = FormatCompatibilitySummary(
                result.RunnableRuleCount,
                result.PartiallyRunnableRuleCount,
                result.UnsupportedRuleCount);
            StatusMessage = result.ReachedMaxFindings
                ? $"Showing first {Findings.Count} Sigma finding(s). {compatibilitySuffix}{diagnosticSuffix}"
                : $"Found {Findings.Count} Sigma finding(s). {compatibilitySuffix}{diagnosticSuffix}";
            if (riskUpdate != null)
            {
                StatusMessage = $"{StatusMessage} {riskUpdate.Diagnostic}".Trim();
                if (riskUpdate.Completed)
                {
                    RiskProjectionUpdated?.Invoke(this, riskUpdate);
                }
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Sigma run failed: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
            RunRuleCommand.NotifyCanExecuteChanged();
        }
    }

    private bool CanRunRule()
    {
        return _featureAccess.CanExecute(FeatureIds.SearchAndSigma, _rules.Count > 0 && !IsRunning);
    }

    private bool CanStartOperation()
    {
        return _featureAccess.CanExecute(FeatureIds.SearchAndSigma, !IsRunning);
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public void Clear()
    {
        if (!RequirePublished())
        {
            return;
        }

        Findings = new ObservableCollection<SigmaFinding>();
        RebuildFindingsView();
        SelectedFinding = null;
        StatusMessage = HasRule
            ? "Sigma findings cleared."
            : "Import a Sigma YAML rule to run against staged telemetry.";
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(IsEmpty));
    }

    [RelayCommand(CanExecute = nameof(CanOpenFinding))]
    public void OpenFinding()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (SelectedFinding == null)
        {
            return;
        }

        NavigateToFinding(SelectedFinding);
    }

    private void NavigateToFinding(SigmaFinding finding)
    {
        _navigateToResult(new TelemetrySearchResult
        {
            Kind = "Sigma",
            RecordKey = $"{finding.RuleId}:{finding.SourceKind}:{finding.TimestampUtc:O}",
            TimestampUtc = finding.TimestampUtc,
            ProcessKey = finding.ProcessKey,
            ProcessEntityId = finding.ProcessEntityId,
            ProcessId = finding.ProcessId,
            ProcessName = finding.ProcessName,
            Title = finding.RuleTitle,
            Subtitle = finding.Evidence,
            MatchedField = finding.MatchedField,
            MatchedValue = finding.MatchedValue,
            Source = finding.Source,
            EvidenceKind = "Sigma finding",
            CorrelationState = finding.CorrelationState,
            CorrelationMethod = finding.CorrelationMethod,
            CorrelationCandidateCount = finding.CorrelationCandidateCount,
            CorrelationDiagnostics = finding.Evidence
        });
    }

    private bool CanOpenFinding()
    {
        return _featureAccess.CanExecute(FeatureIds.SearchAndSigma, SelectedFinding != null);
    }

    private bool RequirePublished()
    {
        if (_featureAccess.TryAccess(FeatureIds.SearchAndSigma, out var unavailableMessage))
        {
            return true;
        }

        StatusMessage = unavailableMessage;
        return false;
    }

    private bool CanUseFeature() => _featureAccess.IsPublished(FeatureIds.SearchAndSigma);

    private void RebuildFindingsView()
    {
        FindingsView = CollectionViewSource.GetDefaultView(Findings);
        FindingsView.GroupDescriptions.Clear();
        FindingsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(SigmaFinding.RuleTitle)));
        FindingsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(SigmaFinding.SourceKind)));
        FindingsView.SortDescriptions.Clear();
        FindingsView.SortDescriptions.Add(new SortDescription(nameof(SigmaFinding.RuleTitle), ListSortDirection.Ascending));
        FindingsView.SortDescriptions.Add(new SortDescription(nameof(SigmaFinding.SourceKind), ListSortDirection.Ascending));
        FindingsView.SortDescriptions.Add(new SortDescription(nameof(SigmaFinding.TimestampUtc), ListSortDirection.Descending));
    }

    private RuleLoadResult LoadRulesFromFiles(
        IEnumerable<string> files,
        string sourceLabel,
        IEnumerable<SigmaRuleDiagnostic>? seedDiagnostics = null)
    {
        var rules = new List<SigmaRule>();
        var diagnostics = seedDiagnostics?.ToList() ?? new List<SigmaRuleDiagnostic>();
        var fileCount = 0;
        var runnableCount = 0;
        var partiallyRunnableCount = 0;
        var unsupportedCount = 0;

        foreach (var file in files.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(file => file, StringComparer.OrdinalIgnoreCase))
        {
            fileCount++;
            IReadOnlyList<SigmaRule> parsedRules;
            try
            {
                parsedRules = _ruleParser.LoadFromFile(file);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new SigmaRuleDiagnostic
                {
                    Severity = "Error",
                    SourcePath = file,
                    Message = $"Parse failed: {ex.Message}"
                });
                continue;
            }

            foreach (var rule in parsedRules)
            {
                foreach (var warning in rule.ParseWarnings)
                {
                    diagnostics.Add(CreateRuleDiagnostic(rule, "Warning", warning));
                }

                var compatibility = SigmaCompatibilityAnalyzer.Analyze(rule);
                diagnostics.AddRange(compatibility.Diagnostics);
                switch (compatibility.Status)
                {
                    case SigmaCompatibilityStatus.Runnable:
                        runnableCount++;
                        break;
                    case SigmaCompatibilityStatus.PartiallyRunnable:
                        partiallyRunnableCount++;
                        break;
                    default:
                        unsupportedCount++;
                        break;
                }

                if (rule.Selections.Count > 0 && compatibility.Status != SigmaCompatibilityStatus.Unsupported)
                {
                    rules.Add(rule);
                }
                else if (rule.ParseWarnings.Count == 0)
                {
                    diagnostics.Add(CreateRuleDiagnostic(rule, "Warning", "No runnable detection selections were parsed."));
                }
            }
        }

        return new RuleLoadResult(rules, diagnostics, sourceLabel, fileCount, runnableCount, partiallyRunnableCount, unsupportedCount);
    }

    private void ApplyRuleLoadResult(RuleLoadResult result)
    {
        _rules = result.Rules.ToList();
        _importDiagnostics = result.Diagnostics.ToList();
        RulePath = result.SourceLabel;
        Findings = new ObservableCollection<SigmaFinding>();
        RebuildFindingsView();
        SelectedFinding = null;
        SetRuleDiagnostics(_importDiagnostics);

        RuleSummary = _rules.Count switch
        {
            0 => $"No runnable Sigma detections were found in {DescribeRuleSource(result)}.",
            1 => $"{_rules[0].Title} ({_rules[0].Selections.Count} selections)",
            _ => $"{_rules.Count} runnable Sigma rule(s) loaded from {DescribeRuleSource(result)}"
        };
        RuleSummary = $"{RuleSummary} {FormatCompatibilitySummary(result.RunnableCount, result.PartiallyRunnableCount, result.UnsupportedCount)}";

        var warningCount = _importDiagnostics.Count(diagnostic => string.Equals(diagnostic.Severity, "Warning", StringComparison.OrdinalIgnoreCase));
        var infoCount = _importDiagnostics.Count(diagnostic => string.Equals(diagnostic.Severity, "Info", StringComparison.OrdinalIgnoreCase));
        var errorCount = _importDiagnostics.Count(diagnostic => string.Equals(diagnostic.Severity, "Error", StringComparison.OrdinalIgnoreCase));
        var diagnosticSuffix = _importDiagnostics.Count > 0
            ? $" {warningCount} warning(s), {errorCount} error(s), {infoCount} info."
            : string.Empty;
        StatusMessage = $"Imported {_rules.Count} runnable Sigma rule(s) from {result.FileCount} file(s).{diagnosticSuffix}";
    }

    private void ResetLoadedRules(string summary, string status)
    {
        _rules = new List<SigmaRule>();
        _importDiagnostics = new List<SigmaRuleDiagnostic>();
        RuleSummary = summary;
        RulePath = string.Empty;
        SetRuleDiagnostics(Array.Empty<SigmaRuleDiagnostic>());
        StatusMessage = status;
    }

    private void SetRuleDiagnostics(IEnumerable<SigmaRuleDiagnostic> diagnostics)
    {
        RuleDiagnostics = new ObservableCollection<SigmaRuleDiagnostic>(DistinctDiagnostics(diagnostics));
        OnPropertyChanged(nameof(HasRuleDiagnostics));
    }

    private static string DescribeRuleSource(RuleLoadResult result)
    {
        if (result.FileCount <= 1 && File.Exists(result.SourceLabel))
        {
            return Path.GetFileName(result.SourceLabel);
        }

        return $"{result.FileCount} file(s)";
    }

    private static IReadOnlyList<string> EnumerateRuleFiles(string folderPath, List<SigmaRuleDiagnostic> diagnostics)
    {
        var files = new List<string>();
        var pending = new Stack<string>();
        pending.Push(folderPath);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            try
            {
                foreach (var file in Directory.EnumerateFiles(current))
                {
                    if (RuleExtensions.Contains(Path.GetExtension(file)))
                    {
                        files.Add(file);
                    }
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add(new SigmaRuleDiagnostic
                {
                    Severity = "Error",
                    SourcePath = current,
                    Message = $"Could not enumerate rule files: {ex.Message}"
                });
            }

            try
            {
                foreach (var directory in Directory.EnumerateDirectories(current))
                {
                    pending.Push(directory);
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add(new SigmaRuleDiagnostic
                {
                    Severity = "Error",
                    SourcePath = current,
                    Message = $"Could not enumerate subfolders: {ex.Message}"
                });
            }
        }

        return files;
    }

    private static SigmaRuleDiagnostic CreateRuleDiagnostic(SigmaRule rule, string severity, string message)
    {
        return new SigmaRuleDiagnostic
        {
            Severity = severity,
            RuleId = rule.Id,
            RuleTitle = rule.Title,
            SourcePath = rule.SourcePath,
            Message = message
        };
    }

    private static string FormatCompatibilitySummary(int runnableCount, int partiallyRunnableCount, int unsupportedCount)
    {
        return $"Compatibility: {runnableCount} runnable, {partiallyRunnableCount} partial, {unsupportedCount} unsupported.";
    }

    private static IEnumerable<SigmaRuleDiagnostic> DistinctDiagnostics(IEnumerable<SigmaRuleDiagnostic> diagnostics)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var diagnostic in diagnostics)
        {
            var key = string.Join(
                '\u001f',
                diagnostic.Severity,
                diagnostic.RuleId,
                diagnostic.RuleTitle,
                diagnostic.SourcePath,
                diagnostic.Message);
            if (seen.Add(key))
            {
                yield return diagnostic;
            }
        }
    }

    partial void OnIsRunningChanged(bool value)
    {
        OnPropertyChanged(nameof(IsEmpty));
        ImportRuleCommand.NotifyCanExecuteChanged();
        ImportRuleFolderCommand.NotifyCanExecuteChanged();
        RunRuleCommand.NotifyCanExecuteChanged();
    }

    partial void OnSelectedFindingChanged(SigmaFinding? value)
    {
        OpenFindingCommand.NotifyCanExecuteChanged();
        if (value != null && _featureAccess.IsPublished(FeatureIds.SearchAndSigma))
        {
            NavigateToFinding(value);
        }
    }

    private sealed record RuleLoadResult(
        IReadOnlyList<SigmaRule> Rules,
        IReadOnlyList<SigmaRuleDiagnostic> Diagnostics,
        string SourceLabel,
        int FileCount,
        int RunnableCount,
        int PartiallyRunnableCount,
        int UnsupportedCount);
}
