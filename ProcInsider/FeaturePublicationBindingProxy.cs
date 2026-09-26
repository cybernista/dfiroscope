using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

/// <summary>
/// Carries the immutable feature-publication projection into WPF objects, such as
/// DataGridColumn, that do not participate in the visual or logical tree.
/// </summary>
public sealed class FeaturePublicationBindingProxy : Freezable
{
    public static readonly DependencyProperty DataProperty = DependencyProperty.Register(
        nameof(Data),
        typeof(FeaturePublicationViewModel),
        typeof(FeaturePublicationBindingProxy));

    public FeaturePublicationViewModel? Data
    {
        get => (FeaturePublicationViewModel?)GetValue(DataProperty);
        set => SetValue(DataProperty, value);
    }

    protected override Freezable CreateInstanceCore() => new FeaturePublicationBindingProxy();
}
