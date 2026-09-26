namespace ProcInsider.ViewModels;

/// <summary>
/// Display-only value identity for an unloaded slot. Equality survives boxing and
/// eviction without retaining a placeholder cache proportional to the result count.
/// This deliberately is not a ProcessRowViewModel and has no process/evidence key.
/// </summary>
public readonly record struct ProcessListingPlaceholder
{
    private readonly object _owner;
    internal int Index { get; }

    internal ProcessListingPlaceholder(object owner, int index)
    {
        _owner = owner;
        Index = index;
    }

    internal bool BelongsTo(object owner) => ReferenceEquals(_owner, owner);
    public bool IsLoadingPlaceholder => true;
    public string ProcessNameDisplay => "Loading...";
    public override string ToString() => ProcessNameDisplay;
}
