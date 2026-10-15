using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ProcInsider.Views.Features.Ai;

public partial class AiConversationLayoutView : UserControl
{
    public static readonly DependencyProperty ConversationProperty = DependencyProperty.Register(
        nameof(Conversation), typeof(object), typeof(AiConversationLayoutView));
    public static readonly DependencyProperty TechnicalDetailsVisibleProperty = DependencyProperty.Register(
        nameof(TechnicalDetailsVisible), typeof(bool), typeof(AiConversationLayoutView),
        new PropertyMetadata(true, (control, _) => ((AiConversationLayoutView)control).ApplyDetailsVisibility()));
    public static readonly DependencyProperty ToggleTechnicalDetailsCommandProperty = DependencyProperty.Register(
        nameof(ToggleTechnicalDetailsCommand), typeof(ICommand), typeof(AiConversationLayoutView));

    private GridLength _conversationWidth = new(8, GridUnitType.Star);
    private GridLength _detailsWidth = new(2, GridUnitType.Star);
    private bool _detailsCollapsed;

    public object? Conversation { get => GetValue(ConversationProperty); set => SetValue(ConversationProperty, value); }
    public bool TechnicalDetailsVisible { get => (bool)GetValue(TechnicalDetailsVisibleProperty); set => SetValue(TechnicalDetailsVisibleProperty, value); }
    public ICommand? ToggleTechnicalDetailsCommand { get => (ICommand?)GetValue(ToggleTechnicalDetailsCommandProperty); set => SetValue(ToggleTechnicalDetailsCommandProperty, value); }

    public AiConversationLayoutView() => InitializeComponent();

    // A GridSplitter writes local widths. Preserve the analyst's split across hide/show.
    private void ApplyDetailsVisibility()
    {
        var columns = ConversationLayout.ColumnDefinitions;
        if (!TechnicalDetailsVisible && !_detailsCollapsed)
        {
            _conversationWidth = columns[0].Width;
            _detailsWidth = columns[2].ActualWidth > 0 ? columns[2].Width : new(2, GridUnitType.Star);
            columns[0].Width = new(1, GridUnitType.Star);
            columns[1].Width = new(0);
            columns[2].Width = new(0);
            _detailsCollapsed = true;
        }
        else if (TechnicalDetailsVisible && _detailsCollapsed)
        {
            columns[0].Width = _conversationWidth;
            columns[1].Width = new(6);
            columns[2].Width = _detailsWidth;
            _detailsCollapsed = false;
        }
    }
}
