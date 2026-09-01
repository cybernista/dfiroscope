namespace ProcInsider.ViewModels;

/// <summary>
/// Represents a single displayable property row in a details surface.
/// </summary>
public class PropertyItemViewModel
{
    public PropertyItemViewModel(string group, string name, string value)
    {
        Group = group;
        Name = name;
        Value = value;
    }

    public string Group { get; }

    public string Name { get; }

    public string Value { get; }
}
