using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public enum ExplorerSelectionGesture
{
    Replace,
    Toggle,
    Range
}

public partial class ExplorerViewModel : ViewModelBase
{
    private const int MaxEvidenceRootNodes = 50;

    private readonly Action<ExplorerScope> _scopeSelected;
    private readonly Func<ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>> _loadChildrenAsync;
    private readonly FeatureAccessService _featureAccess;
    private readonly Dictionary<ExplorerScopeKind, ExplorerNodeViewModel> _nodesByKind = new();
    private readonly Dictionary<string, ExplorerNodeViewModel> _selectedScopeNodes = new(StringComparer.Ordinal);
    private readonly HashSet<string> _greenIncludedScopeIds = new(StringComparer.Ordinal);
    private readonly HashSet<string> _explicitExcludedScopeIds = new(StringComparer.Ordinal);

    private ExplorerNodeViewModel? _caseSessionRoot;
    private ExplorerNodeViewModel? _processOwners;
    private ExplorerNodeViewModel? _processExecutionRoots;
    private ExplorerNodeViewModel? _usersRoot;
    private ExplorerNodeViewModel? _lastSelectedNode;

    [ObservableProperty]
    private ExplorerNodeViewModel? selectedNode;

    [ObservableProperty]
    private string selectedScopeTitle = "All Processes";

    [ObservableProperty]
    private string selectedScopeDescription = "All staged and live process records.";

    [ObservableProperty]
    private string statusMessage = "Explorer scopes are ready.";

    public ExplorerViewModel(
        Action<ExplorerScope> scopeSelected,
        Func<ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>>? loadChildrenAsync = null,
        FeatureAccessService? featureAccess = null)
    {
        _scopeSelected = scopeSelected;
        _loadChildrenAsync = loadChildrenAsync ?? (_ => Task.FromResult<IReadOnlyList<ExplorerNodeViewModel>>(Array.Empty<ExplorerNodeViewModel>()));
        _featureAccess = featureAccess ?? new FeatureAccessService(CurrentEducationalReleaseProfile.RuntimeCatalog);
        BuildExploreTree();
        SelectedNode = _nodesByKind[ExplorerScopeKind.AllProcesses];
    }

    public ObservableCollection<ExplorerNodeViewModel> RootNodes { get; } = [];

    public ExplorerScope CurrentScope => SelectedNode?.Scope ?? _nodesByKind[ExplorerScopeKind.AllProcesses].Scope;

    public IReadOnlyList<ExplorerScope> SelectedScopes
    {
        get
        {
            var scopes = _selectedScopeNodes.Values
                .Where(node => !node.IsPlaceholder)
                .Select(node => node.Scope)
                .ToList();

            if (scopes.Count == 0 && SelectedNode is { IsPlaceholder: false } selectedNode)
            {
                scopes.Add(selectedNode.Scope);
            }

            return scopes;
        }
    }

    public IReadOnlyList<ExplorerScope> VisibleIncludedScopes => FlattenNodes(RootNodes)
        .Where(node => node is { IsPlaceholder: false, CanSelectScope: true } &&
                       node.SelectionState is ExplorerScopeSelectionState.GreenIncluded)
        .Select(node => node.Scope)
        .ToList();

    public IReadOnlyList<ExplorerScope> VisibleExcludedScopes => FlattenNodes(RootNodes)
        .Where(node => node is { IsPlaceholder: false, CanSelectScope: true } &&
                       _explicitExcludedScopeIds.Contains(node.Scope.StableId))
        .Select(node => node.Scope)
        .ToList();

    public IReadOnlyList<ExplorerScope> SelectedNodeAndLoadedDescendantScopes => SelectedNode is { IsPlaceholder: false } selectedNode
        ? FlattenNodes(new[] { selectedNode })
            .Where(node => node is { IsPlaceholder: false, CanSelectScope: true })
            .Select(node => node.Scope)
            .ToList()
        : [];

    public void SelectNode(ExplorerNodeViewModel? node, ExplorerSelectionGesture gesture = ExplorerSelectionGesture.Replace)
    {
        if (node == null || node.IsPlaceholder)
        {
            return;
        }

        if (!FeatureNavigationPolicy.IsScopePublished(_featureAccess, node.Scope))
        {
            StatusMessage =
                $"Explorer scope '{node.Title}' is not published in educational release '{_featureAccess.Catalog.ReleaseId}'.";
            return;
        }

        ApplySelectionGesture(node, gesture);
        SelectedNode = node;
        SelectedScopeTitle = node.Title;
        SelectedScopeDescription = node.Description;
        _scopeSelected(node.Scope);
    }

    public async Task ExpandNodeAsync(ExplorerNodeViewModel? node)
    {
        if (node == null || node.IsPlaceholder || !node.HasLazyChildren || node.ChildrenLoaded)
        {
            return;
        }

        node.StartLoadingChildren();
        try
        {
            var children = await _loadChildrenAsync(node.Scope);
            var publishedChildren = children
                .Where(child => FeatureNavigationPolicy.IsScopePublished(_featureAccess, child.Scope))
                .ToList();
            IReadOnlyList<ExplorerNodeViewModel> nodesToShow = publishedChildren.Count > 0
                ? publishedChildren
                : new[] { ExplorerNodeViewModel.CreatePlaceholder("No child records in the active snapshot") };
            node.ReplaceChildren(nodesToShow);
            ApplyScopeSelectionStateToTree();
        }
        catch (Exception ex)
        {
            node.ReplaceChildren(new[] { ExplorerNodeViewModel.CreatePlaceholder("Child loading failed") });
            StatusMessage = $"Explorer child loading failed: {ex.Message}";
        }
        finally
        {
            node.FinishLoadingChildren();
        }
    }

    public void RefreshCounts(ExplorerScopeCounts counts)
    {
        SetCount(ExplorerScopeKind.CaseSessionRoot, TotalEvidenceCount(counts));
        SetCount(ExplorerScopeKind.ProcessTrees, counts.TotalProcesses);
        SetCount(ExplorerScopeKind.AllProcesses, counts.TotalProcesses);
        SetCount(ExplorerScopeKind.RunningProcesses, counts.RunningProcesses);
        SetCount(ExplorerScopeKind.ExitedProcesses, counts.ExitedProcesses);
        SetCount(ExplorerScopeKind.NotFoundProcesses, counts.NotFoundProcesses);
        SetCount(ExplorerScopeKind.ProcessOwners, counts.TotalProcesses);
        SetCount(ExplorerScopeKind.Bookmarked, counts.BookmarkedProcesses);
        SetCount(ExplorerScopeKind.FilesystemRoot, counts.FilesystemArtifactCount);
        SetCount(ExplorerScopeKind.FilesystemEvidenceRoots, counts.FilesystemArtifactCount);
        SetCount(ExplorerScopeKind.FilesystemArtifacts, counts.FilesystemArtifactCount);
        SetCount(ExplorerScopeKind.NetworkRoot, counts.NetworkCaptureCount + counts.ZeekNetworkArtifactCount);
        SetCount(ExplorerScopeKind.NetworkCaptures, counts.NetworkCaptureCount);
        SetCount(ExplorerScopeKind.ZeekArtifacts, counts.ZeekNetworkArtifactCount);
        SetCount(ExplorerScopeKind.AnalysisRoot, counts.SearchResultCount + counts.SigmaFindingCount + counts.UnresolvedEvidenceCount + counts.AmbiguousEvidenceCount);
        SetCount(ExplorerScopeKind.SearchResults, counts.SearchResultCount);
        SetCount(ExplorerScopeKind.SigmaFindings, counts.SigmaFindingCount);
        SetCount(ExplorerScopeKind.CorrelationEvidence, counts.UnresolvedEvidenceCount + counts.AmbiguousEvidenceCount);
        SetCount(ExplorerScopeKind.UnresolvedEvidence, counts.UnresolvedEvidenceCount);
        SetCount(ExplorerScopeKind.AmbiguousEvidence, counts.AmbiguousEvidenceCount);
        SetCount(ExplorerScopeKind.ArtifactRoot, counts.ModuleProcesses + counts.HandleProcesses + counts.MemoryDumpCount + counts.PeAnalysisCount);
        SetCount(ExplorerScopeKind.Modules, counts.ModuleProcesses);
        SetCount(ExplorerScopeKind.Handles, counts.HandleProcesses);
        SetCount(ExplorerScopeKind.MemoryDumps, counts.MemoryDumpCount);
        SetCount(ExplorerScopeKind.PeAnalyses, counts.PeAnalysisCount);
        SetCount(ExplorerScopeKind.RuntimeEvents, CountSource(counts, "Runtime"));
        SetCount(ExplorerScopeKind.EtwEvents, CountSource(counts, "ETW"));
        SetCount(ExplorerScopeKind.SecurityEvents, CountSource(counts, "Security"));
        SetCount(ExplorerScopeKind.PowerShellEvents, CountSource(counts, "PowerShell"));
        SetCount(ExplorerScopeKind.WindowsOtherEvents, CountSource(counts, "WindowsOther"));
        SetCount(ExplorerScopeKind.SysmonEvents, CountSource(counts, "Sysmon"));
        SetCount(ExplorerScopeKind.SystemActivityRoot, counts.SystemActivityCount);
        SetCount(ExplorerScopeKind.ActivityAuthentication, CountSystemActivity(counts, SystemActivityScopeKind.Authentication));
        SetCount(ExplorerScopeKind.ActivitySuccessfulLogons, CountSystemActivity(counts, SystemActivityScopeKind.SuccessfulLogons));
        SetCount(ExplorerScopeKind.ActivityFailedLogons, CountSystemActivity(counts, SystemActivityScopeKind.FailedLogons));
        SetCount(ExplorerScopeKind.ActivityRemoteInteractive, CountSystemActivity(counts, SystemActivityScopeKind.RemoteInteractive));
        SetCount(ExplorerScopeKind.ActivityExplicitCredentialUse, CountSystemActivity(counts, SystemActivityScopeKind.ExplicitCredentialUse));
        SetCount(ExplorerScopeKind.ActivityPrivilegedLogons, CountSystemActivity(counts, SystemActivityScopeKind.PrivilegedLogons));
        SetCount(ExplorerScopeKind.ActivityAccounts, CountSystemActivity(counts, SystemActivityScopeKind.Accounts));
        SetCount(ExplorerScopeKind.ActivityCreatedUsers, CountSystemActivity(counts, SystemActivityScopeKind.CreatedUsers));
        SetCount(ExplorerScopeKind.ActivityDisabledDeletedUsers, CountSystemActivity(counts, SystemActivityScopeKind.DisabledDeletedUsers));
        SetCount(ExplorerScopeKind.ActivityPasswordChanges, CountSystemActivity(counts, SystemActivityScopeKind.PasswordChanges));
        SetCount(ExplorerScopeKind.ActivityGroups, CountSystemActivity(counts, SystemActivityScopeKind.Groups));
        SetCount(ExplorerScopeKind.ActivityLocalAdministratorsChanges, CountSystemActivity(counts, SystemActivityScopeKind.LocalAdministratorsChanges));
        SetCount(ExplorerScopeKind.ActivitySecurityGroupMembershipChanges, CountSystemActivity(counts, SystemActivityScopeKind.SecurityGroupMembershipChanges));
        SetCount(ExplorerScopeKind.ActivityPolicyAudit, CountSystemActivity(counts, SystemActivityScopeKind.PolicyAudit));
        SetCount(ExplorerScopeKind.ActivityAuditPolicyChanged, CountSystemActivity(counts, SystemActivityScopeKind.AuditPolicyChanged));
        SetCount(ExplorerScopeKind.ActivityLogIntegrity, CountSystemActivity(counts, SystemActivityScopeKind.LogIntegrity));
        SetCount(ExplorerScopeKind.ActivitySecurityLogCleared, CountSystemActivity(counts, SystemActivityScopeKind.SecurityLogCleared));
        SetCount(ExplorerScopeKind.ActivityServicesTasks, CountSystemActivity(counts, SystemActivityScopeKind.ServicesTasks));
        SetCount(ExplorerScopeKind.ActivityServicesInstalled, CountSystemActivity(counts, SystemActivityScopeKind.ServicesInstalled));
        SetCount(ExplorerScopeKind.ActivityScheduledTasksChanged, CountSystemActivity(counts, SystemActivityScopeKind.ScheduledTasksChanged));
        SetCount(ExplorerScopeKind.UsersRoot, counts.SystemActivityAccountCount);

        StatusMessage = $"{counts.TotalProcesses} processes indexed across forensic roots.";
    }

    public void RefreshEvidenceRoots(IReadOnlyList<EvidenceRootSummary> roots)
    {
        RefreshCaseSessionRoots(roots);
        RefreshProcessExecutionRoots(roots);
        PruneSelectedNodes();
        ApplyScopeSelectionStateToTree();
    }

    public void ResetCounts()
    {
        foreach (var node in _nodesByKind.Values)
        {
            node.UpdateCount(0);
        }

        RefreshEvidenceRoots([]);
        PruneSelectedNodes();
        StatusMessage = "Explorer scopes are empty.";
    }

    public void ResetSelection()
    {
        if (!_nodesByKind.TryGetValue(ExplorerScopeKind.AllProcesses, out var allProcesses))
        {
            return;
        }

        SelectedNode = allProcesses;
        SelectedScopeTitle = allProcesses.Title;
        SelectedScopeDescription = allProcesses.Description;
        ClearScopeSelection();
        AddScopeSelection(allProcesses);
        _lastSelectedNode = allProcesses;
    }

    public void ApplyScopeSelectionState(IEnumerable<string> greenIncludedScopeIds, IEnumerable<string> explicitExcludedScopeIds)
    {
        _greenIncludedScopeIds.Clear();
        foreach (var scopeId in greenIncludedScopeIds.Where(id => !string.IsNullOrWhiteSpace(id)))
        {
            _greenIncludedScopeIds.Add(scopeId);
        }

        _explicitExcludedScopeIds.Clear();
        foreach (var scopeId in explicitExcludedScopeIds.Where(id => !string.IsNullOrWhiteSpace(id)))
        {
            _explicitExcludedScopeIds.Add(scopeId);
        }

        ApplyScopeSelectionStateToTree();
    }

    private void BuildExploreTree()
    {
        _caseSessionRoot = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.CaseSessionRoot,
            ScopeId = "root:case-session",
            Title = "Case / Session",
            Description = "Evidence grouped by case, session, capture, host, and execution identity."
        });

        var processTrees = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessTrees,
            ScopeId = "root:process-trees",
            Title = "Process Trees",
            Description = "Process records grouped by execution roots and status scopes."
        });

        var processStatus = Branch("Process Status", "Common process status and analyst annotation scopes.");
        processStatus.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.AllProcesses,
            ScopeId = "process:all",
            Title = "All Processes",
            Description = "All staged and live process records."
        }));
        processStatus.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.RunningProcesses,
            ScopeId = "process:status:running",
            Title = "Running",
            Description = "Processes currently marked as running.",
            Status = ProcessStatus.Running
        }));
        processStatus.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ExitedProcesses,
            ScopeId = "process:status:exited",
            Title = "Exited",
            Description = "Processes that exited after being observed.",
            Status = ProcessStatus.Exited
        }));
        processStatus.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.NotFoundProcesses,
            ScopeId = "process:status:not-found",
            Title = "Not Found",
            Description = "Processes that could not be refreshed or enriched.",
            Status = ProcessStatus.NotFound
        }));
        processStatus.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.Bookmarked,
            ScopeId = "process:annotations",
            Title = "Bookmarked / Noted",
            Description = "Process targets with analyst bookmarks or notes."
        }));

        _processExecutionRoots = Branch("Execution Roots", "Capture/execution roots from the active snapshot.");
        _processExecutionRoots.Children.Add(ExplorerNodeViewModel.CreatePlaceholder("Refresh from db to load execution roots"));
        _processOwners = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessOwners,
            ScopeId = "process:owners",
            Title = "Process Owners",
            Description = "Process records grouped by normalized owning user account."
        });
        _processOwners.MarkChildrenLazy();
        processTrees.Children.Add(_processExecutionRoots);
        processTrees.Children.Add(processStatus);
        processTrees.Children.Add(_processOwners);

        var systemActivity = ActivityNode(
            ExplorerScopeKind.SystemActivityRoot,
            "System Activity",
            "Normalized account, authentication, policy, service, task, and log integrity events.",
            SystemActivityScopeKind.All);
        var authentication = ActivityNode(
            ExplorerScopeKind.ActivityAuthentication,
            "Authentication",
            "Logon, logoff, explicit credential use, and privileged logon activity.",
            SystemActivityScopeKind.Authentication);
        authentication.Children.Add(ActivityNode(ExplorerScopeKind.ActivitySuccessfulLogons, "Successful logons", "Successful Windows logon events.", SystemActivityScopeKind.SuccessfulLogons));
        authentication.Children.Add(ActivityNode(ExplorerScopeKind.ActivityFailedLogons, "Failed logons", "Failed Windows logon attempts.", SystemActivityScopeKind.FailedLogons));
        authentication.Children.Add(ActivityNode(ExplorerScopeKind.ActivityRemoteInteractive, "Remote interactive / RDP", "Remote interactive and RDP logon activity.", SystemActivityScopeKind.RemoteInteractive));
        authentication.Children.Add(ActivityNode(ExplorerScopeKind.ActivityExplicitCredentialUse, "Explicit credential use", "Events where credentials were explicitly supplied.", SystemActivityScopeKind.ExplicitCredentialUse));
        authentication.Children.Add(ActivityNode(ExplorerScopeKind.ActivityPrivilegedLogons, "Privileged logons", "Special or privileged logon activity.", SystemActivityScopeKind.PrivilegedLogons));
        systemActivity.Children.Add(authentication);

        var accounts = ActivityNode(
            ExplorerScopeKind.ActivityAccounts,
            "Accounts",
            "User account lifecycle and password activity.",
            SystemActivityScopeKind.Accounts);
        accounts.Children.Add(ActivityNode(ExplorerScopeKind.ActivityCreatedUsers, "Created users", "User account creation events.", SystemActivityScopeKind.CreatedUsers));
        accounts.Children.Add(ActivityNode(ExplorerScopeKind.ActivityDisabledDeletedUsers, "Disabled/deleted users", "User disable and delete events.", SystemActivityScopeKind.DisabledDeletedUsers));
        accounts.Children.Add(ActivityNode(ExplorerScopeKind.ActivityPasswordChanges, "Password changes/resets", "User password change and reset events.", SystemActivityScopeKind.PasswordChanges));
        systemActivity.Children.Add(accounts);

        var groups = ActivityNode(
            ExplorerScopeKind.ActivityGroups,
            "Groups",
            "Security group membership changes.",
            SystemActivityScopeKind.Groups);
        groups.Children.Add(ActivityNode(ExplorerScopeKind.ActivityLocalAdministratorsChanges, "Local Administrators changes", "Privileged local or domain administrator group changes.", SystemActivityScopeKind.LocalAdministratorsChanges));
        groups.Children.Add(ActivityNode(ExplorerScopeKind.ActivitySecurityGroupMembershipChanges, "Security group membership changes", "Security-enabled group member add/remove events.", SystemActivityScopeKind.SecurityGroupMembershipChanges));
        systemActivity.Children.Add(groups);

        var policyAudit = ActivityNode(
            ExplorerScopeKind.ActivityPolicyAudit,
            "Policy / Audit",
            "Audit policy and security policy changes.",
            SystemActivityScopeKind.PolicyAudit);
        policyAudit.Children.Add(ActivityNode(ExplorerScopeKind.ActivityAuditPolicyChanged, "Audit policy changed", "Audit and security policy change events.", SystemActivityScopeKind.AuditPolicyChanged));
        systemActivity.Children.Add(policyAudit);

        var logIntegrity = ActivityNode(
            ExplorerScopeKind.ActivityLogIntegrity,
            "Log Integrity",
            "Log clear and log integrity events.",
            SystemActivityScopeKind.LogIntegrity);
        logIntegrity.Children.Add(ActivityNode(ExplorerScopeKind.ActivitySecurityLogCleared, "Security log cleared", "Security or system log cleared events.", SystemActivityScopeKind.SecurityLogCleared));
        systemActivity.Children.Add(logIntegrity);

        var servicesTasks = ActivityNode(
            ExplorerScopeKind.ActivityServicesTasks,
            "Services / Tasks",
            "Service installation and scheduled task creation/change events.",
            SystemActivityScopeKind.ServicesTasks);
        servicesTasks.Children.Add(ActivityNode(ExplorerScopeKind.ActivityServicesInstalled, "Services installed", "Windows service installation events.", SystemActivityScopeKind.ServicesInstalled));
        servicesTasks.Children.Add(ActivityNode(ExplorerScopeKind.ActivityScheduledTasksChanged, "Scheduled tasks created/changed", "Scheduled task creation or change events.", SystemActivityScopeKind.ScheduledTasksChanged));
        systemActivity.Children.Add(servicesTasks);

        _usersRoot = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.UsersRoot,
            ScopeId = "users:activity",
            Title = "Users",
            Description = "Accounts observed in normalized system activity.",
            SystemActivityScope = SystemActivityScopeKind.All
        });
        _usersRoot.MarkChildrenLazy();

        var filesystem = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.FilesystemRoot,
            ScopeId = "root:filesystem",
            Title = "Filesystem",
            Description = "Imported NTFS, Prefetch, and file metadata artifacts."
        });
        filesystem.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.FilesystemArtifacts,
            ScopeId = "filesystem:all",
            Title = "All Filesystem Artifacts",
            Description = "All imported filesystem artifact rows."
        }));
        var filesystemRoots = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.FilesystemEvidenceRoots,
            ScopeId = "filesystem:roots",
            Title = "Artifact Roots",
            Description = "Imported filesystem artifacts grouped by case/session/capture/source identity."
        });
        filesystemRoots.MarkChildrenLazy();
        filesystem.Children.Add(filesystemRoots);
        var folders = new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.FilesystemFolder,
            ScopeId = "filesystem:folders",
            Title = "Folders",
            Description = "Bounded folder roots derived from imported artifact paths."
        }, count: -1);
        folders.MarkChildrenLazy();
        filesystem.Children.Add(folders);

        var network = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.NetworkRoot,
            ScopeId = "root:network",
            Title = "Network",
            Description = "Packet capture segments and imported Zeek network artifacts."
        });
        var captures = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.NetworkCaptures,
            ScopeId = "network:captures",
            Title = "PCAP Segments",
            Description = "Agent-owned Packet Monitor capture segment metadata."
        });
        captures.MarkChildrenLazy();
        network.Children.Add(captures);
        network.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ZeekArtifacts,
            ScopeId = "network:zeek",
            Title = "Zeek Artifacts",
            Description = "Imported Zeek conn/dns/http artifacts and process correlations."
        }));

        var analysis = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.AnalysisRoot,
            ScopeId = "root:analysis",
            Title = "Search / Sigma / Correlation",
            Description = "Current search results, Sigma findings, and unresolved or ambiguous evidence."
        });
        analysis.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.SearchResults,
            ScopeId = "analysis:search",
            Title = "Search Results",
            Description = "Current staged telemetry search results."
        }));
        analysis.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.SigmaFindings,
            ScopeId = "analysis:sigma",
            Title = "Sigma Findings",
            Description = "Current Sigma rule findings."
        }));
        var correlation = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.CorrelationEvidence,
            ScopeId = "analysis:correlation",
            Title = "Evidence Correlation",
            Description = "Process-bearing evidence grouped by active correlation state, source, and evidence type."
        });
        var unresolved = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.UnresolvedEvidence,
            ScopeId = "analysis:correlation:unresolved",
            Title = "Unresolved",
            Description = "Evidence for which no compatible scoped process candidate is currently known.",
            CorrelationState = EvidenceCorrelationState.Unresolved
        });
        unresolved.MarkChildrenLazy();
        var ambiguous = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.AmbiguousEvidence,
            ScopeId = "analysis:correlation:ambiguous",
            Title = "Ambiguous",
            Description = "Evidence with multiple equally valid scoped process candidates; no target was selected.",
            CorrelationState = EvidenceCorrelationState.Ambiguous
        });
        ambiguous.MarkChildrenLazy();
        correlation.Children.Add(unresolved);
        correlation.Children.Add(ambiguous);
        analysis.Children.Add(correlation);

        var artifacts = Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ArtifactRoot,
            ScopeId = "root:artifacts",
            Title = "Artifacts",
            Description = "Process-linked artifacts and future evidence roots."
        });
        artifacts.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.Modules,
            ScopeId = "artifacts:modules",
            Title = "Modules",
            Description = "Processes with staged module observations.",
            ArtifactScope = ExplorerArtifactScope.Modules
        }));
        artifacts.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.Handles,
            ScopeId = "artifacts:handles",
            Title = "Handles",
            Description = "Processes with staged handle observations.",
            ArtifactScope = ExplorerArtifactScope.Handles
        }));
        artifacts.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.MemoryDumps,
            ScopeId = "artifacts:memory-dumps",
            Title = "Memory Dumps",
            Description = "Process dump metadata rows."
        }));
        artifacts.Children.Add(Node(new ExplorerScope
        {
            Kind = ExplorerScopeKind.PeAnalyses,
            ScopeId = "artifacts:pe-analyses",
            Title = "PE Analyses",
            Description = "Processes with on-disk process-image PE analysis metadata.",
            RequiredPeAnalysisSourceKind = PeAnalysisSourceKind.ProcessImage
        }));

        var eventSources = Branch("Event Sources", "Processes with events from a telemetry source.");
        eventSources.Children.Add(EventNode(ExplorerScopeKind.RuntimeEvents, "Runtime Events", "Runtime"));
        eventSources.Children.Add(EventNode(ExplorerScopeKind.EtwEvents, "ETW Providers", "ETW"));
        eventSources.Children.Add(EventNode(ExplorerScopeKind.SecurityEvents, "Windows Audit Log", "Security"));
        eventSources.Children.Add(EventNode(ExplorerScopeKind.PowerShellEvents, "PowerShell Logs", "PowerShell"));
        eventSources.Children.Add(EventNode(ExplorerScopeKind.WindowsOtherEvents, "Windows Logs (Other)", "WindowsOther"));
        eventSources.Children.Add(EventNode(ExplorerScopeKind.SysmonEvents, "Sysmon", "Sysmon"));
        artifacts.Children.Add(eventSources);

        RootNodes.Add(processTrees);
        RootNodes.Add(systemActivity);
        RootNodes.Add(_usersRoot);
        RootNodes.Add(filesystem);
        RootNodes.Add(network);
        RootNodes.Add(analysis);
        RootNodes.Add(artifacts);
        PruneUnpublishedNodes(RootNodes);

        RefreshEvidenceRoots([]);
        ResetSelection();
    }

    private void PruneUnpublishedNodes(ObservableCollection<ExplorerNodeViewModel> nodes)
    {
        for (var index = nodes.Count - 1; index >= 0; index--)
        {
            var node = nodes[index];
            PruneUnpublishedNodes(node.Children);
            var featureId = FeatureNavigationPolicy.GetFeatureForExplorerScope(node.Scope);
            var unpublished = featureId.HasValue && !_featureAccess.IsPublished(featureId.Value);
            var emptyFeatureBranch = node.Children.Count == 0 &&
                                     (node.Scope.Kind is ExplorerScopeKind.AnalysisRoot or ExplorerScopeKind.ArtifactRoot ||
                                      node.Scope.Kind == ExplorerScopeKind.Branch && node.Title == "Event Sources");
            if (unpublished || emptyFeatureBranch)
            {
                nodes.RemoveAt(index);
            }
        }
    }

    private void RefreshCaseSessionRoots(IReadOnlyList<EvidenceRootSummary> roots)
    {
        if (_caseSessionRoot == null)
        {
            return;
        }

        SynchronizeChildren(
            _caseSessionRoot.Children,
            roots.Take(MaxEvidenceRootNodes).Select(BuildEvidenceRootNode).ToList(),
            "Refresh from db to load evidence roots");
    }

    private void RefreshProcessExecutionRoots(IReadOnlyList<EvidenceRootSummary> roots)
    {
        if (_processExecutionRoots == null)
        {
            return;
        }

        SynchronizeChildren(
            _processExecutionRoots.Children,
            roots
                .Where(root => root.ProcessCount > 0)
                .Take(MaxEvidenceRootNodes)
                .Select(root =>
                {
                    var node = BuildProcessExecutionRootNode(root);
                    node.MarkChildrenLazy();
                    return node;
                })
                .ToList(),
            "No process executions in the active snapshot");
    }

    private static void SynchronizeChildren(
        ObservableCollection<ExplorerNodeViewModel> children,
        IReadOnlyList<ExplorerNodeViewModel> desiredNodes,
        string emptyPlaceholder)
    {
        var desired = desiredNodes.Count > 0
            ? desiredNodes
            : [ExplorerNodeViewModel.CreatePlaceholder(emptyPlaceholder)];

        for (var desiredIndex = 0; desiredIndex < desired.Count; desiredIndex++)
        {
            var desiredNode = desired[desiredIndex];
            var existingIndex = IndexOfScopeId(children, desiredNode.Scope.StableId);
            if (existingIndex >= 0)
            {
                var existingNode = children[existingIndex];
                existingNode.UpdateCount(desiredNode.Count);
                if (existingIndex != desiredIndex)
                {
                    children.Move(existingIndex, desiredIndex);
                }

                continue;
            }

            children.Insert(desiredIndex, desiredNode);
        }

        var desiredScopeIds = desired
            .Select(node => node.Scope.StableId)
            .ToHashSet(StringComparer.Ordinal);
        for (var index = children.Count - 1; index >= desired.Count; index--)
        {
            children.RemoveAt(index);
        }

        for (var index = children.Count - 1; index >= 0; index--)
        {
            if (!desiredScopeIds.Contains(children[index].Scope.StableId))
            {
                children.RemoveAt(index);
            }
        }
    }

    private static int IndexOfScopeId(IReadOnlyList<ExplorerNodeViewModel> nodes, string scopeId)
    {
        for (var index = 0; index < nodes.Count; index++)
        {
            if (string.Equals(nodes[index].Scope.StableId, scopeId, StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private ExplorerNodeViewModel BuildEvidenceRootNode(EvidenceRootSummary root)
    {
        var scope = new ExplorerScope
        {
            Kind = ExplorerScopeKind.EvidenceRoot,
            ScopeId = BuildIdentityScopeId("evidence", root),
            Title = BuildEvidenceRootTitle(root),
            Description = BuildEvidenceRootDescription(root),
            CaseId = EmptyToNull(root.CaseId),
            EvidenceSessionId = EmptyToNull(root.EvidenceSessionId),
            CaptureId = EmptyToNull(root.CaptureId),
            SourceIdentityId = EmptyToNull(root.SourceIdentityId),
            HostId = EmptyToNull(root.HostId),
            ExecutionRootId = EmptyToNull(root.ExecutionRootId)
        };

        return new ExplorerNodeViewModel(scope, TotalRootCount(root));
    }

    private ExplorerNodeViewModel BuildProcessExecutionRootNode(EvidenceRootSummary root)
    {
        var scope = new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessExecutionRoot,
            ScopeId = BuildIdentityScopeId("process-execution", root),
            Title = BuildProcessExecutionTitle(root),
            Description = BuildEvidenceRootDescription(root),
            CaseId = EmptyToNull(root.CaseId),
            EvidenceSessionId = EmptyToNull(root.EvidenceSessionId),
            CaptureId = EmptyToNull(root.CaptureId),
            SourceIdentityId = EmptyToNull(root.SourceIdentityId),
            HostId = EmptyToNull(root.HostId),
            ExecutionRootId = EmptyToNull(root.ExecutionRootId)
        };

        return new ExplorerNodeViewModel(scope, root.ProcessCount);
    }

    private ExplorerNodeViewModel Branch(string title, string description)
    {
        return new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.Branch,
            ScopeId = $"branch:{title}",
            Title = title,
            Description = description
        }, count: -1);
    }

    private ExplorerNodeViewModel EventNode(ExplorerScopeKind kind, string title, string source)
    {
        return Node(new ExplorerScope
        {
            Kind = kind,
            ScopeId = $"events:{source}",
            Title = title,
            Description = $"Processes with staged {title.ToLowerInvariant()} records.",
            EventSource = source
        });
    }

    private ExplorerNodeViewModel ActivityNode(
        ExplorerScopeKind kind,
        string title,
        string description,
        SystemActivityScopeKind scope)
    {
        return Node(new ExplorerScope
        {
            Kind = kind,
            ScopeId = $"system-activity:{scope}",
            Title = title,
            Description = description,
            SystemActivityScope = scope
        });
    }

    private ExplorerNodeViewModel Node(ExplorerScope scope)
    {
        var node = new ExplorerNodeViewModel(scope);
        _nodesByKind[scope.Kind] = node;
        return node;
    }

    private void SetCount(ExplorerScopeKind kind, int value)
    {
        if (_nodesByKind.TryGetValue(kind, out var node))
        {
            node.UpdateCount(value);
        }
    }

    private static int CountSource(ExplorerScopeCounts counts, string source)
    {
        return counts.EventProcessesBySource.TryGetValue(source, out var count)
            ? count
            : 0;
    }

    private static int CountSystemActivity(ExplorerScopeCounts counts, SystemActivityScopeKind scope)
    {
        return counts.SystemActivityCountsByScope.TryGetValue(scope, out var count)
            ? count
            : 0;
    }

    private static int TotalEvidenceCount(ExplorerScopeCounts counts)
    {
        return counts.TotalProcesses +
               counts.MemoryDumpCount +
               counts.PeAnalysisCount +
               counts.NetworkCaptureCount +
               counts.ZeekNetworkArtifactCount +
               counts.FilesystemArtifactCount +
               counts.SystemActivityCount;
    }

    private static int TotalRootCount(EvidenceRootSummary root)
    {
        return root.ProcessCount +
               root.EventCount +
               root.ModuleCount +
               root.HandleCount +
               root.NetworkCaptureCount +
               root.FilesystemArtifactCount +
               root.SourceRunCount;
    }

    private static string BuildIdentityScopeId(string prefix, EvidenceRootSummary root)
    {
        return string.Join(
            "|",
            prefix,
            root.CaseId,
            root.EvidenceSessionId,
            root.CaptureId,
            root.SourceIdentityId,
            root.HostId,
            root.ExecutionRootId);
    }

    private static string BuildEvidenceRootTitle(EvidenceRootSummary root)
    {
        if (!string.IsNullOrWhiteSpace(root.CaptureId))
        {
            return $"Capture {ShortId(root.CaptureId)}";
        }

        if (!string.IsNullOrWhiteSpace(root.EvidenceSessionId))
        {
            return $"Session {ShortId(root.EvidenceSessionId)}";
        }

        return "Default Evidence Root";
    }

    private static string BuildProcessExecutionTitle(EvidenceRootSummary root)
    {
        if (!string.IsNullOrWhiteSpace(root.ExecutionRootId))
        {
            return $"Execution {ShortId(root.ExecutionRootId)}";
        }

        if (!string.IsNullOrWhiteSpace(root.CaptureId))
        {
            return $"Capture {ShortId(root.CaptureId)}";
        }

        return "Current Execution";
    }

    private static string BuildEvidenceRootDescription(EvidenceRootSummary root)
    {
        ArgumentNullException.ThrowIfNull(root);
        return "Processes grouped within this evidence scope.";
    }

    private static string ShortId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "<default>";
        }

        return value.Length <= 18
            ? value
            : $"{value[..8]}...{value[^6..]}";
    }

    private static string? EmptyToNull(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private void ApplySelectionGesture(ExplorerNodeViewModel node, ExplorerSelectionGesture gesture)
    {
        switch (gesture)
        {
            case ExplorerSelectionGesture.Toggle:
                if (node.IsScopeSelected)
                {
                    RemoveScopeSelection(node);
                }
                else
                {
                    AddScopeSelection(node);
                }

                _lastSelectedNode = node;
                break;
            case ExplorerSelectionGesture.Range:
                var range = GetSiblingRange(_lastSelectedNode, node);
                if (range.Count == 0)
                {
                    ClearScopeSelection();
                    AddScopeSelection(node);
                }
                else
                {
                    ClearScopeSelection();
                    foreach (var rangeNode in range)
                    {
                        AddScopeSelection(rangeNode);
                    }
                }

                _lastSelectedNode = node;
                break;
            default:
                ClearScopeSelection();
                AddScopeSelection(node);
                _lastSelectedNode = node;
                break;
        }

        if (_selectedScopeNodes.Count == 0)
        {
            AddScopeSelection(node);
        }
    }

    private void AddScopeSelection(ExplorerNodeViewModel node)
    {
        if (node.IsPlaceholder)
        {
            return;
        }

        _selectedScopeNodes[node.Scope.StableId] = node;
        node.IsScopeSelected = true;
    }

    private void RemoveScopeSelection(ExplorerNodeViewModel node)
    {
        _selectedScopeNodes.Remove(node.Scope.StableId);
        node.IsScopeSelected = false;
    }

    private void ClearScopeSelection()
    {
        foreach (var node in _selectedScopeNodes.Values)
        {
            node.IsScopeSelected = false;
        }

        _selectedScopeNodes.Clear();
    }

    private void PruneSelectedNodes()
    {
        var liveScopeIds = FlattenNodes(RootNodes).Select(node => node.Scope.StableId).ToHashSet(StringComparer.Ordinal);
        foreach (var node in _selectedScopeNodes.Values.Where(node => !liveScopeIds.Contains(node.Scope.StableId)).ToList())
        {
            RemoveScopeSelection(node);
        }
    }

    private IReadOnlyList<ExplorerNodeViewModel> GetSiblingRange(ExplorerNodeViewModel? anchor, ExplorerNodeViewModel node)
    {
        if (anchor == null)
        {
            return [];
        }

        return FindSiblingRange(RootNodes, anchor, node) ?? [];
    }

    private static IReadOnlyList<ExplorerNodeViewModel>? FindSiblingRange(
        IReadOnlyList<ExplorerNodeViewModel> siblings,
        ExplorerNodeViewModel anchor,
        ExplorerNodeViewModel node)
    {
        var anchorIndex = IndexOf(siblings, anchor);
        var nodeIndex = IndexOf(siblings, node);
        if (anchorIndex >= 0 && nodeIndex >= 0)
        {
            var start = Math.Min(anchorIndex, nodeIndex);
            var end = Math.Max(anchorIndex, nodeIndex);
            return siblings
                .Skip(start)
                .Take(end - start + 1)
                .Where(sibling => !sibling.IsPlaceholder)
                .ToList();
        }

        foreach (var sibling in siblings)
        {
            var match = FindSiblingRange(sibling.Children, anchor, node);
            if (match != null)
            {
                return match;
            }
        }

        return null;
    }

    private static int IndexOf(IReadOnlyList<ExplorerNodeViewModel> nodes, ExplorerNodeViewModel target)
    {
        for (var i = 0; i < nodes.Count; i++)
        {
            if (ReferenceEquals(nodes[i], target))
            {
                return i;
            }
        }

        return -1;
    }

    private void ApplyScopeSelectionStateToTree()
    {
        foreach (var root in RootNodes)
        {
            ApplyScopeSelectionState(root, inheritedIncluded: false, inheritedExcluded: false);
            ApplyGreenDescendantState(root);
        }
    }

    private void ApplyScopeSelectionState(
        ExplorerNodeViewModel node,
        bool inheritedIncluded,
        bool inheritedExcluded)
    {
        var scopeId = node.Scope.StableId;
        var isExplicitlyExcluded = _explicitExcludedScopeIds.Contains(scopeId);
        var isExplicitlyIncluded = _greenIncludedScopeIds.Contains(scopeId);
        var isExcluded = inheritedExcluded || isExplicitlyExcluded;
        var isIncluded = !isExcluded && (inheritedIncluded || isExplicitlyIncluded);

        node.IsGreenIncludedDirectly = !isExcluded && isExplicitlyIncluded;
        node.SelectionState = isIncluded
            ? ExplorerScopeSelectionState.GreenIncluded
            : ExplorerScopeSelectionState.Neutral;

        foreach (var child in node.Children)
        {
            ApplyScopeSelectionState(
                child,
                inheritedIncluded: isIncluded,
                inheritedExcluded: isExcluded);
        }
    }

    private static bool ApplyGreenDescendantState(ExplorerNodeViewModel node)
    {
        var hasGreenIncludedDescendant = false;
        foreach (var child in node.Children)
        {
            hasGreenIncludedDescendant |= child.IsGreenIncludedDirectly || ApplyGreenDescendantState(child);
        }

        node.HasGreenIncludedDescendant = hasGreenIncludedDescendant;
        return node.IsGreenIncludedDirectly || hasGreenIncludedDescendant;
    }

    private static IEnumerable<ExplorerNodeViewModel> FlattenNodes(IEnumerable<ExplorerNodeViewModel> nodes)
    {
        foreach (var node in nodes)
        {
            yield return node;

            foreach (var child in FlattenNodes(node.Children))
            {
                yield return child;
            }
        }
    }
}
