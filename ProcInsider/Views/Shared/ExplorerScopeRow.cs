using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ProcInsider.Views.Shared;

/// <summary>Presentation only: the node retains its count, state and feature-owned scope command.</summary>
public sealed class ExplorerScopeRow : Control
{
    public static readonly DependencyProperty LabelProperty = DependencyProperty.Register(
        nameof(Label), typeof(string), typeof(ExplorerScopeRow));
    public static readonly DependencyProperty LabelToolTipProperty = DependencyProperty.Register(
        nameof(LabelToolTip), typeof(object), typeof(ExplorerScopeRow));
    public static readonly DependencyProperty ToggleCommandProperty = DependencyProperty.Register(
        nameof(ToggleCommand), typeof(ICommand), typeof(ExplorerScopeRow));
    public static readonly DependencyProperty ToggleVisibilityProperty = DependencyProperty.Register(
        nameof(ToggleVisibility), typeof(Visibility), typeof(ExplorerScopeRow), new PropertyMetadata(Visibility.Visible));

    public string Label { get => (string)GetValue(LabelProperty); set => SetValue(LabelProperty, value); }
    public object LabelToolTip { get => GetValue(LabelToolTipProperty); set => SetValue(LabelToolTipProperty, value); }
    public ICommand ToggleCommand { get => (ICommand)GetValue(ToggleCommandProperty); set => SetValue(ToggleCommandProperty, value); }
    public Visibility ToggleVisibility { get => (Visibility)GetValue(ToggleVisibilityProperty); set => SetValue(ToggleVisibilityProperty, value); }
}
