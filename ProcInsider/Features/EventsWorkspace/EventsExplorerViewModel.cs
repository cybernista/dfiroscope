using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.ViewModels;
using ProcInsider.Models.InvestigationWorkspaces;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed record EventsPivot(EventAggregateDimension Dimension, EventAggregate Aggregate, EventIdentityRole Role,
    EventsReadBinding Binding) : INotifyPropertyChanged
{
    public EventAggregate Aggregate { get; private set; } = Aggregate;
    public bool IsCategory { get; init; }
    public EventsPivot? Parent { get; internal set; }
    public EventGreenSelector Selector => new(Family(Dimension), Aggregate.ParentKey ?? Aggregate.Key,
        Family(Dimension) == EventAggregateDimension.Identity ? Role : EventIdentityRole.Actor, AllValues: IsCategory,
        ChildKey: Dimension is EventAggregateDimension.IdentitySession or EventAggregateDimension.AuditSubcategory ? Aggregate.Key : null);
    internal static EventAggregateDimension Family(EventAggregateDimension dimension) => dimension switch
    { EventAggregateDimension.IdentitySession => EventAggregateDimension.Identity, EventAggregateDimension.AuditSubcategory => EventAggregateDimension.Auditing, _ => dimension };
    public ObservableCollection<object> Children { get; } = [];
    internal Action<EventsPivot>? Expand { get; set; }
    internal long ChildReadRevision { get; set; }
    private bool _expanded, _descendant;
    public bool IsExpanded { get => _expanded; set { if (_expanded == value) return; _expanded = value; PropertyChanged?.Invoke(this, new(nameof(IsExpanded))); if (value) Expand?.Invoke(this); } }
    private bool _green;
    public bool IsGreenIncludedDirectly { get => _green; init => _green = value; }
    public event PropertyChangedEventHandler? PropertyChanged;
    internal void Update(EventsPivot next)
    {
        if (Aggregate == next.Aggregate && _green == next._green && _descendant == next._descendant) return;
        Aggregate = next.Aggregate; _green = next._green; _descendant = next._descendant;
        PropertyChanged?.Invoke(this, new(null));
    }
    public bool HasGreenIncludedDescendant { get => _descendant; init => _descendant = value; }
    public string ScopeGlyph => IsGreenIncludedDirectly ? "G" : "";
    public string ScopeStateDescription => "Toggle green selection: OR within this category, AND between categories.";
    public string Display => $"{(Aggregate.Label ?? (Aggregate.Identity is { } identity ? EventsWorkspaceRowViewModel.IdentityDisplay(identity) : Aggregate.Key.Length == 0 ? "Unknown / missing" : Aggregate.Key))} ({Aggregate.EventCount:N0})";
    public string ToolTip => Aggregate.Description ?? (Aggregate.Identity is { } identity
        ? $"{identity.Role}; {identity.Status}; {identity.Scope}; {identity.NativePrefix}; {identity.Key}" : Aggregate.Key);
}
internal sealed record EventsCategoryPlaceholder(string Display);

/// <summary>One fixed Sysmon taxonomy node. Counts are populated only after a successful, current read.</summary>
internal sealed class SysmonExplorerNode : ViewModelBase
{
    private long? _count = 0;
    private bool _expanded;
    private bool _isGreenIncludedDirectly;
    private bool _hasGreenIncludedDescendant;
    internal SysmonExplorerNode(string name, string description, IReadOnlyList<int> eventIds, EventsReadBinding binding,
        bool isLeaf = false, bool canGreenSelect = false)
    {
        Name = name; Description = description; EventIds = eventIds; Binding = binding; IsLeaf = isLeaf; CanGreenSelect = canGreenSelect;
    }
    public string Name { get; }
    public string Description { get; }
    public IReadOnlyList<int> EventIds { get; }
    public EventsReadBinding Binding { get; }
    public bool IsLeaf { get; }
    public bool CanGreenSelect { get; }
    public ObservableCollection<SysmonExplorerNode> Children { get; } = [];
    internal Action? Expand { get; set; }
    public bool IsExpanded { get => _expanded; set { if (SetProperty(ref _expanded, value) && value) Expand?.Invoke(); } }
    public string Display => IsLeaf ? $"{Name} - ID {EventIds.Single()}" + CountSuffix : Name + CountSuffix;
    public string ToolTip => IsLeaf
        ? $"{Description} Sysmon Event ID {EventIds.Single()}; badge is the recorded evidence-row count."
        : $"{Description} Badge is the recorded evidence-row count for these fixed Sysmon Event IDs.";
    public bool IsGreenIncludedDirectly => _isGreenIncludedDirectly;
    public bool HasGreenIncludedDescendant => _hasGreenIncludedDescendant;
    public string ScopeGlyph => IsGreenIncludedDirectly ? "G" : "";
    public string ScopeStateDescription => "Toggle Sysmon green selection; it combines with other green event categories.";
    private string CountSuffix => _count is { } count ? $" ({count:N0})" : "";
    internal void UpdateCounts(IReadOnlyDictionary<int, long> counts)
    {
        _count = EventIds.Sum(id => counts[id]);
        foreach (var child in Children) child.UpdateCounts(counts);
        OnPropertyChanged(nameof(Display));
    }
    internal void ClearCounts(bool knownEmpty = false)
    {
        _count = knownEmpty ? 0 : null;
        foreach (var child in Children) child.ClearCounts(knownEmpty);
        OnPropertyChanged(nameof(Display));
    }
    internal void ProjectGreen(IReadOnlyCollection<int> selectedEventIds)
    {
        var isGreenIncludedDirectly = CanGreenSelect && EventIds.All(selectedEventIds.Contains);
        var hasGreenIncludedDescendant = CanGreenSelect && !isGreenIncludedDirectly && EventIds.Any(selectedEventIds.Contains);
        if (_isGreenIncludedDirectly == isGreenIncludedDirectly && _hasGreenIncludedDescendant == hasGreenIncludedDescendant) return;
        _isGreenIncludedDirectly = isGreenIncludedDirectly;
        _hasGreenIncludedDescendant = hasGreenIncludedDescendant;
        OnPropertyChanged(nameof(IsGreenIncludedDirectly));
        OnPropertyChanged(nameof(HasGreenIncludedDescendant));
        OnPropertyChanged(nameof(ScopeGlyph));
    }
}

internal sealed class EventsExplorerSection : ViewModelBase
{
    private readonly EventsExplorerViewModel _owner;
    private bool _expanded;
    private long? _count = 0;
    public EventAggregateDimension Dimension { get; }
    public string Header
    {
        get
        {
            var title = Dimension switch
            {
                EventAggregateDimension.EventId => "By Event ID",
                EventAggregateDimension.Auditing => "By Audit Category",
                _ => Dimension.ToString()
            };
            return _count is { } count ? $"{title} ({count:N0})" : title;
        }
    }
    public bool IsExpanded { get => _expanded; set { if (SetProperty(ref _expanded, value) && value) _owner.StartLoad(this); } }
    public ObservableCollection<EventsPivot> Pivots { get; } = [];
    public ObservableCollection<object> Children { get; } = [new EventsCategoryPlaceholder("Expand to read recorded evidence.")];
    private string _status = "Expand to read recorded evidence.";
    public string Status { get => _status; internal set => SetProperty(ref _status, value); }
    private bool _green, _descendant;
    public bool IsGreenIncludedDirectly => _green;
    public bool HasGreenIncludedDescendant => _descendant;
    public string ScopeGlyph => _green ? "G" : "";
    public string ScopeStateDescription => "Toggle this whole category; child buttons can exclude individual values.";
    internal void ProjectGreen(IReadOnlyList<EventGreenSelector> selectors, EventIdentityRole role)
    {
        _green = selectors.Any(s => s.Dimension == Dimension && s.AllValues && (Dimension != EventAggregateDimension.Identity || s.Role == role));
        _descendant = selectors.Any(s => s.Dimension == Dimension && !s.AllValues && !s.IsExcluded && (Dimension != EventAggregateDimension.Identity || s.Role == role));
        OnPropertyChanged(nameof(IsGreenIncludedDirectly)); OnPropertyChanged(nameof(HasGreenIncludedDescendant)); OnPropertyChanged(nameof(ScopeGlyph));
    }
    internal EventsExplorerSection(EventsExplorerViewModel owner, EventAggregateDimension dimension)
    {
        _owner = owner; Dimension = dimension;
    }
    internal void UpdateCount(long? count)
    {
        if (_count == count) return;
        _count = count;
        OnPropertyChanged(nameof(Header));
    }
}

internal sealed class EventsExplorerViewModel : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly EventsWorkspaceReadSession _session;
    private CancellationTokenSource _reads = new();
    private readonly HashSet<Task> _work = [];
    private readonly Dictionary<EventsExplorerSection, long> _revisions = [];
    private bool _suspended, _disposed;
    private EventIdentityRole _role = EventIdentityRole.Actor;
    public EventIdentityRole IdentityRole { get => _role; set { if (SetProperty(ref _role, value)) { Invalidate(); ReloadExpanded(); } } }
    public Array IdentityRoles => Enum.GetValues<EventIdentityRole>();
    private long? _eventCount = 0;
    private EventsReadBinding? _countBinding;
    private CancellationTokenSource _countRead = new();
    private Task? _countTask;
    private string _countStatus = "";
    private readonly bool _includeSysmon;
    private long _sysmonRevision;
    private EventsReadBinding? _sysmonCountBinding;
    private Task? _sysmonCountTask;
    private bool _sysmonReloadPending;
    private string _sysmonStatus = "";
    public string Header => _eventCount is { } count ? $"Events ({count:N0})" :
        _countStatus.Length > 0 ? "Events (…)" : "Events";
    private bool _expanded;
    public bool IsExpanded { get => _expanded; set => SetProperty(ref _expanded, value); }
    public string Status => string.Join(" ", new[] { _countStatus, _sysmonStatus }.Concat(Sections.Where(s => s.Status.StartsWith("Unavailable:", StringComparison.Ordinal) || s.Status == "Read canceled.").Select(s => $"{s.Header}: {s.Status}"))).Trim();
    public IRelayCommand<EventIdentityRole> SetIdentityRoleCommand { get; }
    public IReadOnlyList<EventsExplorerSection> Sections { get; }
    public SysmonExplorerNode? Sysmon { get; private set; }
    public ObservableCollection<object> Children { get; } = [];
    public IRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand<EventsPivot> SelectCommand { get; }
    public IAsyncRelayCommand<EventsPivot> OpenNewCommand { get; }
    public IAsyncRelayCommand<SysmonExplorerNode> SelectSysmonCommand { get; }
    public IAsyncRelayCommand<SysmonExplorerNode> OpenNewSysmonCommand { get; }
    public IAsyncRelayCommand<SysmonExplorerNode> ToggleSysmonGreenCommand { get; }
    public IAsyncRelayCommand<EventsPivot> ToggleGreenCommand { get; }
    public IAsyncRelayCommand<EventsExplorerSection> ToggleCategoryGreenCommand { get; }
    internal EventsExplorerViewModel(WorkspaceManager manager, EventsWorkspaceReadSession session, bool includeWindowsSecurityFacets, bool includeSysmon)
    {
        _manager = manager; _session = session; _includeSysmon = includeSysmon;
        Sections = new[] { EventAggregateDimension.Provider, EventAggregateDimension.Channel, EventAggregateDimension.EventId }
            .Concat(includeWindowsSecurityFacets || includeSysmon ? [EventAggregateDimension.Identity] : [])
            .Concat(includeWindowsSecurityFacets ? [EventAggregateDimension.Auditing] : [])
            .Select(d => new EventsExplorerSection(this, d)).ToArray();
        foreach (var section in Sections) Children.Add(section);
        RefreshCommand = new RelayCommand(ReloadExpanded);
        SetIdentityRoleCommand = new RelayCommand<EventIdentityRole>(role => IdentityRole = role);
        SelectCommand = new AsyncRelayCommand<EventsPivot>(pivot => NavigateAsync(pivot, false));
        OpenNewCommand = new AsyncRelayCommand<EventsPivot>(pivot => NavigateAsync(pivot, true));
        SelectSysmonCommand = new AsyncRelayCommand<SysmonExplorerNode>(node => NavigateSysmonAsync(node, false));
        OpenNewSysmonCommand = new AsyncRelayCommand<SysmonExplorerNode>(node => NavigateSysmonAsync(node, true));
        ToggleSysmonGreenCommand = new AsyncRelayCommand<SysmonExplorerNode>(node => node is not { CanGreenSelect: true }
            ? Task.CompletedTask : _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Events, _manager.Navigation.Capture, SysmonNode: node), toggleGreen: true));
        ToggleGreenCommand = new AsyncRelayCommand<EventsPivot>(pivot => pivot == null ? Task.CompletedTask :
            _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Events, _manager.Navigation.Capture, EventPivot: pivot), toggleGreen: true));
        ToggleCategoryGreenCommand = new AsyncRelayCommand<EventsExplorerSection>(section => section == null || _session.Binding is not { } binding
            ? Task.CompletedTask : _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Events, _manager.Navigation.Capture,
                EventPivot: new(section.Dimension, new("", 0, null), IdentityRole, binding) { IsCategory = true }), toggleGreen: true));
        if (_includeSysmon && _session.Binding is { } binding)
            Sysmon = CreateSysmonRoot(binding);
        manager.ActiveContextChanged += ReloadExpanded;
    }
    internal void BindActivityRoots(IEnumerable<ExplorerNodeViewModel> roots)
    {
        var desired = Sections.Cast<object>().Concat(Sysmon == null ? [] : new object[] { Sysmon }).Concat(roots).ToArray();
        foreach (var removed in Children.Where(child => !desired.Contains(child)).ToArray()) Children.Remove(removed);
        for (var i = 0; i < desired.Length; i++)
        {
            var index = Children.IndexOf(desired[i]);
            if (index < 0) Children.Insert(i, desired[i]);
            else if (index != i) Children.Move(index, i);
        }
    }
    private Task NavigateAsync(EventsPivot? pivot, bool openNew) => pivot == null ? Task.CompletedTask :
        _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Events, _manager.Navigation.Capture,
            Mode: openNew ? WorkspaceNavigationMode.OpenNew : WorkspaceNavigationMode.Reuse, EventPivot: pivot));
    private Task NavigateSysmonAsync(SysmonExplorerNode? node, bool openNew) => node == null ? Task.CompletedTask :
        _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Events, _manager.Navigation.Capture,
            Mode: openNew ? WorkspaceNavigationMode.OpenNew : WorkspaceNavigationMode.Reuse, SysmonNode: node));
    private SysmonExplorerNode CreateSysmonRoot(EventsReadBinding binding)
    {
        var root = new SysmonExplorerNode("Sysmon", "Fixed Sysmon taxonomy over authorized recorded evidence.", SysmonEventTaxonomy.EventIds, binding, canGreenSelect: true);
        foreach (var category in SysmonEventTaxonomy.Categories)
        {
            var categoryNode = new SysmonExplorerNode(category.Name, category.Description, category.Events.Select(definition => definition.EventId).ToArray(), binding, canGreenSelect: true);
            foreach (var definition in category.Events)
                categoryNode.Children.Add(new SysmonExplorerNode(definition.Name, definition.Description, [definition.EventId], binding, isLeaf: true, canGreenSelect: true));
            root.Children.Add(categoryNode);
        }
        root.Expand = StartSysmonLoad;
        return root;
    }
    internal void ReloadExpanded()
    {
        if (_suspended || _disposed) return;
        StartCount();
        // Superseded aggregate reads still cancel promptly; only the visible nodes survive.
        _reads.Cancel(); _reads.Dispose(); _reads = new();
        var filter = (_manager.ActiveInstance as EventsWorkspaceViewModel)?.Filter;
        var selectors = filter?.GreenSelectors ?? [];
        foreach (var section in Sections)
        {
            section.ProjectGreen(selectors, IdentityRole);
            if (section.IsExpanded) StartLoad(section);
            else _revisions[section] = _revisions.GetValueOrDefault(section) + 1;
        }
        Sysmon?.ProjectGreen(filter?.GreenSysmonEventIds ?? []);
        foreach (var node in Sysmon?.Children ?? [])
        {
            node.ProjectGreen(filter?.GreenSysmonEventIds ?? []);
            foreach (var leaf in node.Children) leaf.ProjectGreen(filter?.GreenSysmonEventIds ?? []);
        }
        StartSysmonLoad();
    }
    private async void StartCount()
    {
        if (_session.KnownEmpty || _session.Binding == null || _countBinding == _session.Binding || _countTask is { IsCompleted: false }) return;
        var task = _countTask = LoadCountAsync(_countRead.Token);
        _work.Add(task);
        try { await task; } finally { _work.Remove(task); }
    }
    private async Task LoadCountAsync(CancellationToken token)
    {
        var binding = _session.Binding;
        _countStatus = "Reading Events count…";
        OnPropertyChanged(nameof(Header)); OnPropertyChanged(nameof(Status));
        try
        {
            // One bounded row reuses the exact dataset total; never sum overlapping identity groups
            // or derive the root badge from the active workspace's filtered/materialized page.
            var result = await _session.Reader.QueryAsync(new() { PageSize = 1 }, token);
            if (token.IsCancellationRequested || _disposed || _suspended || binding != _session.Binding || result.Binding != binding) return;
            _eventCount = result.MatchingEvents; _countStatus = "";
            var auditCount = Sections.Any(section => section.Dimension == EventAggregateDimension.Auditing)
                ? (await _session.Reader.AggregateAsync(new(), EventAggregateDimension.Auditing, cancellationToken: token)).MatchingEvents
                : (long?)null;
            if (token.IsCancellationRequested || _disposed || _suspended || binding != _session.Binding) return;
            _countBinding = binding;
            foreach (var section in Sections)
                section.UpdateCount(section.Dimension == EventAggregateDimension.Auditing ? auditCount : _eventCount);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            if (token.IsCancellationRequested || _disposed || _suspended || binding != _session.Binding) return;
            _countStatus = $"Events count unavailable: {ex.Message}";
        }
        OnPropertyChanged(nameof(Header)); OnPropertyChanged(nameof(Status));
    }
    private async void StartSysmonLoad()
    {
        if (_session.KnownEmpty || Sysmon == null || _suspended || _disposed || _session.Binding is not { } binding || _sysmonCountBinding == binding) return;
        // ReloadExpanded replaces the facet request token. If that interrupts the current Sysmon read,
        // defer its successor until the canceled task has relinquished the single query service.
        if (_sysmonCountTask is { IsCompleted: false }) { _sysmonReloadPending = true; return; }
        _sysmonReloadPending = false;
        var task = _sysmonCountTask = LoadSysmonAsync(Sysmon, ++_sysmonRevision, _reads.Token);
        _work.Add(task);
        try { await task; }
        finally
        {
            _work.Remove(task);
            if (_sysmonReloadPending && ReferenceEquals(_sysmonCountTask, task))
            {
                _sysmonReloadPending = false;
                StartSysmonLoad();
            }
        }
    }
    private async Task LoadSysmonAsync(SysmonExplorerNode root, long revision, CancellationToken token)
    {
        var binding = _session.Binding;
        _sysmonStatus = "Reading Sysmon counts…";
        OnPropertyChanged(nameof(Status));
        try
        {
            var result = await _session.Reader.SysmonCountsAsync(token);
            if (token.IsCancellationRequested || _disposed || _suspended || binding != _session.Binding ||
                root != Sysmon || result.Binding != binding || revision != _sysmonRevision) return;
            root.UpdateCounts(result.Counts);
            _sysmonCountBinding = binding;
            _sysmonStatus = "";
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            if (token.IsCancellationRequested || _disposed || _suspended || binding != _session.Binding || revision != _sysmonRevision) return;
            root.ClearCounts();
            _sysmonStatus = $"Sysmon counts unavailable: {ex.Message}";
        }
        finally { OnPropertyChanged(nameof(Status)); }
    }
    internal async void StartLoad(EventsExplorerSection section)
    {
        if (_suspended || _disposed) return;
        var task = LoadAsync(section);
        _work.Add(task);
        try { await task; } finally { _work.Remove(task); }
    }
    internal async Task LoadAsync(EventsExplorerSection section)
    {
        if (_suspended || _disposed) return;
        var revision = _revisions[section] = _revisions.GetValueOrDefault(section) + 1;
        var token = _reads.Token;
        var binding = _session.Binding;
        var role = IdentityRole;
        var workspace = _manager.ActiveInstance as EventsWorkspaceViewModel;
        var selected = workspace?.Filter.GreenSelectors ?? [];
        section.ProjectGreen(selected, role);
        var filter = ExplorerFilter(workspace) with { GreenSelectors = selected.Where(s => s.Dimension != section.Dimension).ToArray() };
        // Alternatives retain deliberate green/header criteria from other dimensions; ordinary pivot
        // navigation was removed above so a listing scope cannot zero the global Explorer summary.
        filter = section.Dimension switch
        {
            EventAggregateDimension.Identity => filter with { IdentityKey = null, IdentitySessionKey = null },
            EventAggregateDimension.Provider => filter with { Provider = null },
            EventAggregateDimension.Channel => filter with { Channel = null },
            EventAggregateDimension.Auditing => filter with { AuditCategoryKey = null, AuditSubcategoryKey = null },
            _ => filter with { EventId = null, MissingEventId = false }
        };
        section.Status = "Reading…";
        try
        {
            var pivots = new List<EventsPivot>();
            long offset = 0;
            while (true)
            {
                var result = await _session.Reader.AggregateAsync(filter, section.Dimension, role, offset, 128, token);
                if (token.IsCancellationRequested || _disposed || binding != _session.Binding || revision != _revisions[section]) return;
                foreach (var aggregate in result.Groups)
                {
                    var pivot = new EventsPivot(section.Dimension, aggregate, role, result.Binding);
                    pivots.Add(Mark(pivot, selected));
                }
                offset += result.Groups.Count;
                if (offset >= result.TotalGroups) break;
                if (result.Groups.Count == 0) throw new InvalidOperationException("Incomplete event category read.");
            }
            // Keep selected zero-match values removable when another category rules them out.
            var presentSelectors = pivots.Select(p => p.Selector).ToHashSet();
            foreach (var pivot in workspace?.GreenPivots(section.Dimension, role, binding) ?? [])
                if (presentSelectors.Add(pivot.Selector)) pivots.Add(pivot);
            var existingPivots = section.Pivots.ToDictionary(p => (p.Selector, p.Binding));
            var desired = pivots.Select(pivot =>
            {
                if (!existingPivots.TryGetValue((pivot.Selector, pivot.Binding), out var existing)) return pivot;
                existing.Update(pivot); return existing;
            }).ToArray();
            Synchronize(section.Pivots, desired);
            Synchronize(section.Children, desired.Length > 0 ? desired.Cast<object>().ToArray() :
                [section.Children.OfType<EventsCategoryPlaceholder>().FirstOrDefault(p => p.Display == "No matching events.") ?? new EventsCategoryPlaceholder("No matching events.")]);
            foreach (var pivot in desired)
            {
                if (pivot.Dimension is not (EventAggregateDimension.Identity or EventAggregateDimension.Auditing)) continue;
                pivot.Expand = StartLoadChildren;
                if (pivot.Children.Count == 0) pivot.Children.Add(new EventsCategoryPlaceholder("Expand to read recorded evidence."));
                if (pivot.IsExpanded) StartLoadChildren(pivot);
            }
            section.Status = "";
        }
        catch (OperationCanceledException) { if (revision == _revisions[section]) section.Status = "Read canceled."; }
        catch (Exception ex) { if (!_disposed && revision == _revisions[section]) section.Status = $"Unavailable: {ex.Message}"; }
        finally { OnPropertyChanged(nameof(Status)); }
    }
    private static EventsPivot Mark(EventsPivot pivot, IReadOnlyList<EventGreenSelector> selected) => pivot with
    {
        IsGreenIncludedDirectly = EventGreenSelection.Includes(selected, pivot.Selector),
        HasGreenIncludedDescendant = EventGreenSelection.HasDescendant(selected, pivot.Selector)
    };
    private async void StartLoadChildren(EventsPivot parent)
    {
        var task = LoadChildrenAsync(parent); _work.Add(task);
        try { await task; } finally { _work.Remove(task); }
    }
    internal async Task LoadChildrenAsync(EventsPivot parent)
    {
        if (_suspended || _disposed || parent.Binding != _session.Binding ||
            parent.Dimension is not (EventAggregateDimension.Identity or EventAggregateDimension.Auditing)) return;
        var revision = ++parent.ChildReadRevision;
        var token = _reads.Token;
        var workspace = _manager.ActiveInstance as EventsWorkspaceViewModel;
        var selected = workspace?.Filter.GreenSelectors ?? [];
        var filter = ExplorerFilter(workspace) with { GreenSelectors = selected.Where(s => s.Dimension != parent.Dimension).ToArray() };
        var dimension = parent.Dimension == EventAggregateDimension.Identity ? EventAggregateDimension.IdentitySession : EventAggregateDimension.AuditSubcategory;
        filter = parent.Dimension == EventAggregateDimension.Identity
            ? filter with { IdentityKey = parent.Aggregate.Key, IdentityRole = parent.Role, IdentitySessionKey = null }
            : filter with { AuditCategoryKey = parent.Aggregate.Key, AuditSubcategoryKey = null };
        try
        {
            var children = new List<EventsPivot>();
            long offset = 0;
            while (true)
            {
                var result = await _session.Reader.AggregateAsync(filter, dimension, parent.Role, offset, 128, token);
                if (token.IsCancellationRequested || _disposed || parent.Binding != _session.Binding || revision != parent.ChildReadRevision) return;
                children.AddRange(result.Groups.Select(g => Mark(new(dimension, g, parent.Role, result.Binding) { Parent = parent }, selected)));
                offset += result.Groups.Count;
                if (offset >= result.TotalGroups) break;
                if (result.Groups.Count == 0) throw new InvalidOperationException("Incomplete child aggregate read.");
            }
            var present = children.Select(p => p.Selector).ToHashSet();
            foreach (var child in workspace?.GreenPivots(dimension, parent.Role, parent.Binding) ?? [])
                if (child.Aggregate.ParentKey == parent.Aggregate.Key && present.Add(child.Selector))
                    children.Add(Mark(child with { Parent = parent }, selected));
            var old = parent.Children.OfType<EventsPivot>().ToDictionary(p => p.Selector);
            var desired = children.Select(p => { if (!old.TryGetValue(p.Selector, out var retained)) return p; retained.Update(p); return retained; }).ToArray();
            Synchronize(parent.Children, desired.Length > 0 ? desired.Cast<object>().ToArray() : [new EventsCategoryPlaceholder("No matching events.")]);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!token.IsCancellationRequested && !_disposed && parent.Binding == _session.Binding && revision == parent.ChildReadRevision)
            { parent.Children.Add(new EventsCategoryPlaceholder("Unavailable: " + ex.Message)); }
        }
    }
    internal static void Synchronize<T>(ObservableCollection<T> collection, IReadOnlyList<T> desired) where T : class
    {
        var retained = new HashSet<T>(desired, ReferenceEqualityComparer.Instance);
        for (var i = collection.Count - 1; i >= 0; i--)
            if (!retained.Contains(collection[i])) collection.RemoveAt(i);
        var present = new HashSet<T>(collection, ReferenceEqualityComparer.Instance);
        for (var i = 0; i < desired.Count; i++)
        {
            if (i < collection.Count && ReferenceEquals(collection[i], desired[i])) continue;
            if (present.Add(desired[i])) { collection.Insert(i, desired[i]); continue; }
            var index = collection.IndexOf(desired[i]);
            if (index != i) collection.Move(index, i);
        }
    }
    private static EventsFilter ExplorerFilter(EventsWorkspaceViewModel? workspace) => (workspace?.Filter ?? new()) with
    {
        // Explorer is a capture summary. Ordinary pivot navigation scopes only the listing; letting it
        // leak into sibling badges made a root all-values green toggle appear to "repair" their counts.
        IdentityKey = null,
        IdentitySessionKey = null,
        Provider = null,
        Channel = null,
        EventId = null,
        Source = null,
        EventIds = [],
        MissingEventId = false,
        ExactEvent = null,
        AuditCategoryKey = null,
        AuditSubcategoryKey = null
    };
    internal void Invalidate()
    {
        _countRead.Cancel(); _countRead.Dispose(); _countRead = new();
        _countTask = null; _countBinding = null; _eventCount = _session.KnownEmpty ? 0 : null; _countStatus = "";
        foreach (var section in Sections) section.UpdateCount(_eventCount);
        _sysmonRevision++;
        _sysmonCountBinding = null;
        _sysmonCountTask = null;
        _sysmonReloadPending = false;
        if (_includeSysmon && _session.Binding is { } binding && Sysmon?.Binding != binding)
        {
            if (Sysmon != null) Children.Remove(Sysmon);
            Sysmon = CreateSysmonRoot(binding);
            Children.Insert(Math.Min(Sections.Count, Children.Count), Sysmon);
        }
        Sysmon?.ClearCounts(_session.KnownEmpty); _sysmonStatus = "";
        OnPropertyChanged(nameof(Header));
        _reads.Cancel(); _reads.Dispose(); _reads = new();
        foreach (var section in Sections)
        {
            _revisions[section] = _revisions.GetValueOrDefault(section) + 1;
            section.Pivots.Clear(); section.Children.Clear(); section.Children.Add(new EventsCategoryPlaceholder("Expand to read recorded evidence."));
            section.Status = "Evidence changed; refresh this pivot.";
        }
        OnPropertyChanged(nameof(Status));
    }
    internal async Task QuiesceAsync(CancellationToken token)
    {
        _suspended = true; _reads.Cancel(); _countRead.Cancel();
        while (_work.Where(task => !task.IsCompleted).ToArray() is { Length: > 0 } pending) await Task.WhenAll(pending).WaitAsync(token);
    }
    internal void Resume() { _suspended = false; _reads.Dispose(); _reads = new(); _countRead.Dispose(); _countRead = new(); ReloadExpanded(); }
    public void Dispose() { _disposed = true; _reads.Cancel(); _reads.Dispose(); _countRead.Cancel(); _countRead.Dispose(); _manager.ActiveContextChanged -= ReloadExpanded; }
}
