using System.ComponentModel;
using System.Runtime.CompilerServices;
using ProcInsider.Models.Features;

namespace ProcInsider.ViewModels;

/// <summary>
/// Stable shell-tab metadata with one-time lazy content activation.
/// </summary>
public sealed class FeatureTabDescriptor : INotifyPropertyChanged
{
    private readonly Func<object?> _contentFactory;
    private object? _content;
    private Exception? _activationException;
    private ActivationState _activationState;
    private int? _count;

    public FeatureTabDescriptor(
        FeatureTabKey key,
        string header,
        FeatureId featureId,
        int order,
        Func<object?> contentFactory,
        bool showCount = false)
    {
        if (string.IsNullOrWhiteSpace(header))
        {
            throw new ArgumentException("Feature tabs require a header.", nameof(header));
        }

        if (featureId.IsEmpty)
        {
            throw new ArgumentException("Feature tabs require a release feature ID.", nameof(featureId));
        }

        if (string.IsNullOrWhiteSpace(key.TabId))
        {
            throw new ArgumentException("Feature tabs require a stable key.", nameof(key));
        }

        Key = key;
        BaseHeader = header.Trim();
        FeatureId = featureId;
        Order = order;
        _contentFactory = contentFactory ?? throw new ArgumentNullException(nameof(contentFactory));
        _count = showCount ? 0 : null;
    }

    public FeatureTabKey Key { get; }

    public string BaseHeader { get; }

    public FeatureId FeatureId { get; }

    public int Order { get; }

    public string Header => _count.HasValue ? $"{BaseHeader} ({_count.Value})" : BaseHeader;

    public int? Count => _count;

    public object? Content
    {
        get
        {
            TryActivate(out var content, out _);
            return content;
        }
    }

    public bool IsContentCreated => _activationState == ActivationState.Created;

    public bool HasActivationFailed => _activationState == ActivationState.Failed;

    public string ActivationError => _activationException?.Message ?? string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? ActivationFailed;

    public bool TryActivate(out object? content, out Exception? activationException)
    {
        if (_activationState == ActivationState.NotStarted)
        {
            try
            {
                _content = _contentFactory() ?? throw new InvalidOperationException(
                    $"Tab '{Key}' content is unavailable.");
                _activationState = ActivationState.Created;
            }
            catch (Exception ex)
            {
                _activationException = ex;
                _activationState = ActivationState.Failed;
                ActivationFailed?.Invoke(this, EventArgs.Empty);
            }

            OnPropertyChanged(nameof(Content));
            OnPropertyChanged(nameof(IsContentCreated));
            OnPropertyChanged(nameof(HasActivationFailed));
            OnPropertyChanged(nameof(ActivationError));
        }

        content = _content;
        activationException = _activationException;
        return _activationState == ActivationState.Created;
    }

    public void UpdateCount(int count)
    {
        if (!_count.HasValue)
        {
            return;
        }

        var normalized = Math.Max(0, count);
        if (_count.Value == normalized)
        {
            return;
        }

        _count = normalized;
        OnPropertyChanged(nameof(Count));
        OnPropertyChanged(nameof(Header));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private enum ActivationState
    {
        NotStarted,
        Created,
        Failed
    }
}
