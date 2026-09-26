namespace ProcInsider.Models.Features;

/// <summary>
/// Core-owned stable, release-independent identity for a releasable vertical feature.
/// </summary>
public readonly record struct FeatureId
{
    public FeatureId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Feature IDs cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public bool IsEmpty => string.IsNullOrEmpty(Value);

    public override string ToString() => Value ?? string.Empty;
}
