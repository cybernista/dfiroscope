using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public enum ExplorerScopeSelectionState
{
    Neutral,
    GreenIncluded
}

public partial class ExplorerNodeViewModel : ViewModelBase
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayName))]
    private int count;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScopeGlyph))]
    [NotifyPropertyChangedFor(nameof(ScopeStateDescription))]
    private ExplorerScopeSelectionState selectionState;

    private bool _isGreenIncludedDirectly;
    private bool _hasGreenIncludedDescendant;

    [ObservableProperty]
    private bool isScopeSelected;

    private bool _hasLazyChildren;
    private bool _childrenLoaded = true;
    private bool _isLoadingChildren;

    public ExplorerNodeViewModel(ExplorerScope scope, int count = 0)
    {
        Scope = scope;
        Count = count;
    }

    public ExplorerScope Scope { get; }

    public ObservableCollection<ExplorerNodeViewModel> Children { get; } = [];

    public bool IsPlaceholder => Scope.Kind == ExplorerScopeKind.Placeholder;

    public bool CanSelectScope => !IsPlaceholder && Scope.Kind != ExplorerScopeKind.Branch;

    public bool IsGreenIncludedDirectly
    {
        get => _isGreenIncludedDirectly;
        set
        {
            if (SetProperty(ref _isGreenIncludedDirectly, value))
            {
                OnPropertyChanged(nameof(ScopeGlyph));
                OnPropertyChanged(nameof(ScopeStateDescription));
            }
        }
    }

    public bool HasGreenIncludedDescendant
    {
        get => _hasGreenIncludedDescendant;
        set
        {
            if (SetProperty(ref _hasGreenIncludedDescendant, value))
            {
                OnPropertyChanged(nameof(ScopeStateDescription));
            }
        }
    }

    public bool HasLazyChildren
    {
        get => _hasLazyChildren;
        private set => SetProperty(ref _hasLazyChildren, value);
    }

    public bool ChildrenLoaded
    {
        get => _childrenLoaded;
        private set => SetProperty(ref _childrenLoaded, value);
    }

    public bool IsLoadingChildren
    {
        get => _isLoadingChildren;
        private set => SetProperty(ref _isLoadingChildren, value);
    }

    public string Title => Scope.Title;

    public string Description => Scope.Description;

    public string DisplayName => Count >= 0
        ? $"{Title} ({Count})"
        : Title;

    public string ScopeGlyph => IsGreenIncludedDirectly ? "G" : string.Empty;

    public string ScopeStateDescription => IsGreenIncludedDirectly
        ? "Green-selected; listed evidence from this node is visible."
        : HasGreenIncludedDescendant
            ? "Contains a green-selected descendant."
            : SelectionState == ExplorerScopeSelectionState.GreenIncluded
                ? "Included through a green-selected ancestor; listed evidence from this node is visible."
                : "Not green-selected.";

    public void UpdateCount(int value)
    {
        Count = value;
    }

    public void MarkChildrenLazy()
    {
        HasLazyChildren = true;
        ChildrenLoaded = false;
        Children.Clear();
        Children.Add(CreatePlaceholder("Expand to load children"));
    }

    public void ReplaceChildren(IEnumerable<ExplorerNodeViewModel> children)
    {
        Children.Clear();
        foreach (var child in children)
        {
            Children.Add(child);
        }

        HasLazyChildren = false;
        ChildrenLoaded = true;
        IsLoadingChildren = false;
    }

    public void StartLoadingChildren()
    {
        IsLoadingChildren = true;
        Children.Clear();
        Children.Add(CreatePlaceholder("Loading..."));
    }

    public void FinishLoadingChildren()
    {
        IsLoadingChildren = false;
    }

    public static ExplorerNodeViewModel CreatePlaceholder(string title)
    {
        return new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.Placeholder,
            ScopeId = $"placeholder:{title}",
            Title = title,
            Description = title
        }, count: -1);
    }
}
