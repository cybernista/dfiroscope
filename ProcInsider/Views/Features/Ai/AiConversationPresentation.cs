using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using ProcInsider.Models.Ai;

namespace ProcInsider.Views.Features.Ai;

public sealed class AiMessageTemplateSelector : DataTemplateSelector
{
    public DataTemplate AnalystTemplate { get; set; } = null!;
    public DataTemplate AssistantTemplate { get; set; } = null!;
    public override DataTemplate SelectTemplate(object item, DependencyObject container) =>
        item is AiConversationMessage message && (message.Role.Equals("user", StringComparison.OrdinalIgnoreCase) ||
            message.Role.Equals("analyst", StringComparison.OrdinalIgnoreCase)) ? AnalystTemplate : AssistantTemplate;
}

// WPF input/viewport translation only; commands retain all feature and submission admission.
public static class AiConversationInteraction
{
    public static readonly DependencyProperty SendCommandProperty = DependencyProperty.RegisterAttached(
        "SendCommand", typeof(ICommand), typeof(AiConversationInteraction), new PropertyMetadata(null, SendChanged));
    public static void SetSendCommand(DependencyObject target, ICommand? value) => target.SetValue(SendCommandProperty, value);
    public static ICommand? GetSendCommand(DependencyObject target) => (ICommand?)target.GetValue(SendCommandProperty);
    private static void SendChanged(DependencyObject target, DependencyPropertyChangedEventArgs args)
    {
        if (target is not TextBox composer) return;
        composer.PreviewKeyDown -= ComposerKeyDown;
        if (args.NewValue is not null) composer.PreviewKeyDown += ComposerKeyDown;
    }
    private static void ComposerKeyDown(object sender, KeyEventArgs args)
    {
        if (sender is TextBox composer) args.Handled = HandleComposerKey(composer, args.Key, Keyboard.Modifiers);
    }
    public static bool HandleComposerKey(TextBox composer, Key key, ModifierKeys modifiers)
    {
        if (key != Key.Enter || modifiers != ModifierKeys.None) return false;
        composer.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
        var command = GetSendCommand(composer);
        if (command?.CanExecute(null) == true) command.Execute(null);
        return true; // Enter does not add an accidental newline while a send is busy.
    }

    public static readonly DependencyProperty PassMouseWheelToTranscriptProperty = DependencyProperty.RegisterAttached(
        "PassMouseWheelToTranscript", typeof(bool), typeof(AiConversationInteraction), new PropertyMetadata(false, MouseWheelChanged));
    public static void SetPassMouseWheelToTranscript(DependencyObject target, bool value) => target.SetValue(PassMouseWheelToTranscriptProperty, value);
    public static bool GetPassMouseWheelToTranscript(DependencyObject target) => (bool)target.GetValue(PassMouseWheelToTranscriptProperty);
    private static void MouseWheelChanged(DependencyObject target, DependencyPropertyChangedEventArgs args)
    {
        if (target is not UIElement text) return;
        text.PreviewMouseWheel -= MessageMouseWheel;
        if ((bool)args.NewValue) text.PreviewMouseWheel += MessageMouseWheel;
    }
    private static void MessageMouseWheel(object sender, MouseWheelEventArgs args)
    {
        var ancestor = sender as DependencyObject;
        while (ancestor is not null && ancestor is not ListBox)
            ancestor = VisualTreeHelper.GetParent(ancestor);
        if (ancestor is not ListBox list) return;
        var scroll = FindTranscriptScroll(list);
        if (scroll is null) return;
        scroll.RaiseEvent(new MouseWheelEventArgs(args.MouseDevice, args.Timestamp, args.Delta)
            { RoutedEvent = Mouse.MouseWheelEvent });
        args.Handled = true;
    }
    private static ScrollViewer? FindTranscriptScroll(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is ScrollViewer scroll) return scroll;
            if (FindTranscriptScroll(child) is { } found) return found;
        }
        return null;
    }

    public static readonly DependencyProperty FollowRepliesProperty = DependencyProperty.RegisterAttached(
        "FollowReplies", typeof(bool), typeof(AiConversationInteraction), new PropertyMetadata(false, FollowChanged));
    private static readonly DependencyProperty ViewportProperty = DependencyProperty.RegisterAttached(
        "Viewport", typeof(TranscriptViewport), typeof(AiConversationInteraction));
    public static void SetFollowReplies(DependencyObject target, bool value) => target.SetValue(FollowRepliesProperty, value);
    public static bool GetFollowReplies(DependencyObject target) => (bool)target.GetValue(FollowRepliesProperty);
    private static void FollowChanged(DependencyObject target, DependencyPropertyChangedEventArgs args)
    {
        if (target is not ListBox list) return;
        (list.GetValue(ViewportProperty) as TranscriptViewport)?.Dispose();
        list.SetValue(ViewportProperty, (bool)args.NewValue ? new TranscriptViewport(list) : null);
    }
    private sealed class TranscriptViewport : IDisposable
    {
        private readonly ListBox _list;
        private ScrollViewer? _scroll;
        private bool _nearBottom = true, _pending, _follow, _adjusting, _connected, _readerScrolled;
        private double _offset; private long _epoch;
        public TranscriptViewport(ListBox list)
        {
            _list = list;
            list.Loaded += Loaded; list.Unloaded += Unloaded;
            if (list.IsLoaded) Connect();
        }
        private void Loaded(object sender, RoutedEventArgs args) => Connect();
        private void Unloaded(object sender, RoutedEventArgs args) => Disconnect();
        private void Connect()
        {
            if (_connected) return;
            _list.ApplyTemplate();
            _scroll = FindTranscriptScroll(_list);
            if (_scroll is null) return;
            _connected = true;
            ((INotifyCollectionChanged)_list.Items).CollectionChanged += ItemsChanged;
            _scroll.ScrollChanged += ScrollChanged;
            _list.PreviewMouseWheel += ReaderMouseWheel;
            _list.PreviewKeyDown += ReaderKeyDown;
            _list.AddHandler(ScrollBar.ScrollEvent, new ScrollEventHandler(ReaderScrollBar), true);
            Queue();
        }
        private void Disconnect()
        {
            if (!_connected) return;
            ((INotifyCollectionChanged)_list.Items).CollectionChanged -= ItemsChanged;
            if (_scroll is not null) _scroll.ScrollChanged -= ScrollChanged;
            _list.PreviewMouseWheel -= ReaderMouseWheel;
            _list.PreviewKeyDown -= ReaderKeyDown;
            _list.RemoveHandler(ScrollBar.ScrollEvent, new ScrollEventHandler(ReaderScrollBar));
            _connected = false; _epoch++; _pending = false; _readerScrolled = false;
        }
        private void ScrollChanged(object sender, ScrollChangedEventArgs args)
        {
            if (_adjusting || _scroll is null) return;
            // Real scroll input distinguishes the analyst's newer position from automatic
            // virtualized extent/offset adjustments and Reset's temporary collapse to zero.
            if (_pending && _readerScrolled)
            {
                _offset = _scroll.VerticalOffset;
                _nearBottom = _scroll.ScrollableHeight - _scroll.VerticalOffset <= 40;
            }
            // Scrolling to the end can also change a virtualized panel's estimated extent.
            // Recognize reaching the bottom unless a pending refresh is restoring an earlier position.
            if (!_pending && args.VerticalChange != 0 && _scroll.ScrollableHeight - _scroll.VerticalOffset <= 40)
                _nearBottom = true;
            // New/virtualized messages and pane resizing retain the reader's existing follow intent.
            if (args.ExtentHeightChange != 0 || args.ViewportHeightChange != 0)
            {
                if (_nearBottom && _scroll.ScrollableHeight - _scroll.VerticalOffset > 40) Queue();
                return;
            }
            if (args.VerticalChange != 0)
            {
                _nearBottom = _scroll.ScrollableHeight - _scroll.VerticalOffset <= 40;
                // The analyst can scroll after an append queued its idle refresh.
                // Restore their newer position, never the offset captured before that input.
                if (_pending) _offset = _scroll.VerticalOffset;
            }
        }
        private void ReaderMouseWheel(object sender, MouseWheelEventArgs args) => MarkPendingNavigation();
        private void ReaderKeyDown(object sender, KeyEventArgs args)
        {
            if (args.Key is Key.Up or Key.Down or Key.PageUp or Key.PageDown or Key.Home or Key.End)
                MarkPendingNavigation();
        }
        private void ReaderScrollBar(object sender, ScrollEventArgs args)
        {
            if (args.OriginalSource is ScrollBar { Orientation: Orientation.Vertical }) MarkPendingNavigation();
        }
        private void MarkPendingNavigation()
        {
            if (!_pending || _scroll is null) return;
            _readerScrolled = true;
            _offset = _scroll.VerticalOffset;
            _nearBottom = _scroll.ScrollableHeight - _scroll.VerticalOffset <= 40;
        }
        private void ItemsChanged(object? sender, NotifyCollectionChangedEventArgs args) => Queue();
        private void Queue()
        {
            if (_pending || !_connected || _scroll is null) return;
            _pending = true; _follow = _nearBottom; _offset = _scroll.VerticalOffset;
            var epoch = _epoch;
            _list.Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
            {
                if (epoch != _epoch) return;
                _pending = false; _readerScrolled = false;
                if (!_connected || !_list.IsLoaded || _scroll is null || _list.Items.Count == 0) return;
                _adjusting = true;
                try
                {
                    _list.UpdateLayout();
                    if (_follow && _nearBottom)
                    {
                        _list.ScrollIntoView(_list.Items[^1]);
                        _list.UpdateLayout();
                        _scroll.ScrollToEnd();
                    }
                    else _scroll.ScrollToVerticalOffset(_offset);
                }
                finally { _adjusting = false; }
            }));
        }
        public void Dispose()
        {
            Disconnect(); _list.Loaded -= Loaded; _list.Unloaded -= Unloaded;
        }

    }
}

// Controlled Markdown subset: paragraphs, headings, lists, quotes, emphasis and code.
// Text is never interpreted as XAML/HTML. Links/images stay inert literal text; no navigation or fetching.
public sealed class AiMarkdownTextBlock : RichTextBox
{
    public static readonly DependencyProperty MarkdownProperty = DependencyProperty.Register(nameof(Markdown),
        typeof(string), typeof(AiMarkdownTextBlock), new PropertyMetadata("", Changed));
    public string Markdown { get => (string)GetValue(MarkdownProperty); set => SetValue(MarkdownProperty, value); }
    private readonly Paragraph _paragraph = new() { Margin = new Thickness(0) };
    public InlineCollection Inlines => _paragraph.Inlines;
    public AiMarkdownTextBlock()
    {
        IsReadOnly = true; IsDocumentEnabled = false;
        BorderThickness = new Thickness(0); Padding = new Thickness(0);
        Background = Brushes.Transparent;
        VerticalScrollBarVisibility = ScrollBarVisibility.Disabled;
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled;
        Document = new FlowDocument(_paragraph) { PagePadding = new Thickness(0) };
    }
    private static void Changed(DependencyObject target, DependencyPropertyChangedEventArgs args) =>
        ((AiMarkdownTextBlock)target).Render(args.NewValue as string ?? "");
    private void Render(string text)
    {
        Inlines.Clear();
        if (text.Length > 100_000) text = text[..100_000] + "\n[Display truncated; original retained in conversation history.]";
        var inCode = false;
        var first = true;
        foreach (var line in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("```", StringComparison.Ordinal) || trimmed.StartsWith("~~~", StringComparison.Ordinal))
            { inCode = !inCode; continue; }
            if (!first) Inlines.Add(new LineBreak());
            first = false;
            if (inCode)
            {
                Inlines.Add(new Run(line) { FontFamily = new FontFamily("Consolas"), Background = Brushes.WhiteSmoke });
                continue;
            }
            var content = line;
            var heading = 0;
            while (heading < trimmed.Length && heading < 6 && trimmed[heading] == '#') heading++;
            var span = new Span();
            if (heading > 0 && heading < trimmed.Length && trimmed[heading] == ' ')
            { span.FontWeight = FontWeights.SemiBold; content = trimmed[(heading + 1)..]; }
            else if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed.StartsWith("* ", StringComparison.Ordinal) || trimmed.StartsWith("+ ", StringComparison.Ordinal))
                content = line[..(line.Length - trimmed.Length)] + "• " + trimmed[2..];
            else if (trimmed.StartsWith("> ", StringComparison.Ordinal))
            { span.Foreground = Brushes.DimGray; content = "│ " + trimmed[2..]; }
            AddInline(span.Inlines, content);
            Inlines.Add(span);
        }
    }
    private static void AddInline(InlineCollection target, string text)
    {
        var start = 0;
        while (start < text.Length)
        {
            var token = text[start] == '`' ? "`" : text.AsSpan(start).StartsWith("**", StringComparison.Ordinal) ? "**" : "";
            if (token.Length != 0)
            {
                var end = text.IndexOf(token, start + token.Length, StringComparison.Ordinal);
                if (end > start + token.Length)
                {
                    var run = new Run(text.Substring(start + token.Length, end - start - token.Length));
                    if (token == "`") { run.FontFamily = new FontFamily("Consolas"); run.Background = Brushes.WhiteSmoke; }
                    else run.FontWeight = FontWeights.SemiBold;
                    target.Add(run); start = end + token.Length; continue;
                }
            }
            var next = start + 1;
            while (next < text.Length && text[next] != '`' && !(text[next] == '*' && next + 1 < text.Length && text[next + 1] == '*')) next++;
            target.Add(new Run(text[start..next])); start = next;
        }
    }
}
