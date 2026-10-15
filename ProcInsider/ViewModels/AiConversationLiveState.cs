using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using ProcInsider.Models.Ai;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

internal sealed record AiConversationDraftMetadata(string AnalystInstructions,
    string? RecoveryMessageId, string LastSubmissionDestination, string EvidenceStatus);

/// <summary>
/// Shares unsaved presentation and the current execution by annotation store and saved ID.
/// A presenter owns only a lease; closing one view cannot dispose another view's state.
/// </summary>
internal static class AiConversationLiveState
{
    private static readonly ConditionalWeakTable<AnnotationDatabaseService, StoreEntries> Stores = new();

    internal static AiConversationLiveBinding Bind(AnnotationDatabaseService store, string conversationId,
        INotifyPropertyChanged presenter, ObservableCollection<AiConversationMessage> messages,
        ObservableCollection<AiEvidenceReference> references,
        Func<string> readDraft, Action<string> writeDraft,
        Func<bool> readBusy, Action<bool> writeBusy,
        Func<AiConversationMessage?> readAnswer, Action<AiConversationMessage?> writeAnswer,
        Func<AiEvidenceReference?> readReference, Action<AiEvidenceReference?> writeReference,
        Func<string> readStatus, Action<string> writeStatus,
        Func<string> readProgress, Action<string> writeProgress,
        string draftProperty, string statusProperty,
        Func<AiConversationDraftMetadata> readMetadata, Action<AiConversationDraftMetadata> writeMetadata,
        string? progressProperty = null)
    {
        var entries = Stores.GetValue(store, _ => new StoreEntries());
        Entry entry;
        lock (entries.Gate)
        {
            if (!entries.Items.TryGetValue(conversationId, out entry!))
                entries.Items.Add(conversationId, entry = new Entry());
            entry.Owners++;
        }
        return new AiConversationLiveBinding(entries, conversationId, entry, presenter, messages, references,
            readDraft, writeDraft, readBusy, writeBusy, readAnswer, writeAnswer, readReference, writeReference,
            readStatus, writeStatus, readProgress, writeProgress, draftProperty, statusProperty,
            readMetadata, writeMetadata, progressProperty);
    }

    internal sealed class StoreEntries
    {
        internal readonly object Gate = new();
        internal readonly Dictionary<string, Entry> Items = new(StringComparer.Ordinal);
    }

    internal sealed class Entry
    {
        internal int Owners;
        internal bool HasPresentation;
        internal string Draft = string.Empty;
        internal string Status = string.Empty;
        internal string Progress = string.Empty;
        internal AiConversationDraftMetadata Metadata = new(string.Empty, null, string.Empty, string.Empty);
        internal bool Busy;
        internal AiConversationMessage[] Messages = [];
        internal AiEvidenceReference[] References = [];
        internal string? AnswerId;
        internal string? ReferenceKey;
        internal CancellationTokenSource? Execution;
        internal event Action? Changed;

        internal void Notify() => Changed?.Invoke();
    }

    internal static string? ReferenceIdentity(AiEvidenceReference? reference) =>
        reference?.ReferenceId;
}

internal sealed class AiConversationLiveBinding : IDisposable
{
    private readonly AiConversationLiveState.StoreEntries _entries;
    private readonly string _conversationId;
    private readonly AiConversationLiveState.Entry _entry;
    private readonly INotifyPropertyChanged _presenter;
    private readonly ObservableCollection<AiConversationMessage> _messages;
    private readonly ObservableCollection<AiEvidenceReference> _references;
    private readonly Func<string> _readDraft;
    private readonly Action<string> _writeDraft;
    private readonly Func<bool> _readBusy;
    private readonly Action<bool> _writeBusy;
    private readonly Func<AiConversationMessage?> _readAnswer;
    private readonly Action<AiConversationMessage?> _writeAnswer;
    private readonly Func<AiEvidenceReference?> _readReference;
    private readonly Action<AiEvidenceReference?> _writeReference;
    private readonly Func<string> _readStatus;
    private readonly Action<string> _writeStatus;
    private readonly Func<string> _readProgress;
    private readonly Action<string> _writeProgress;
    private readonly string _draftProperty;
    private readonly string _statusProperty;
    private readonly Func<AiConversationDraftMetadata> _readMetadata;
    private readonly Action<AiConversationDraftMetadata> _writeMetadata;
    private readonly string? _progressProperty;
    private readonly SynchronizationContext? _context = SynchronizationContext.Current;
    private bool _applying;
    private bool _publishing;
    private bool _disposed;

    internal AiConversationLiveBinding(AiConversationLiveState.StoreEntries entries, string conversationId,
        AiConversationLiveState.Entry entry, INotifyPropertyChanged presenter,
        ObservableCollection<AiConversationMessage> messages, ObservableCollection<AiEvidenceReference> references,
        Func<string> readDraft, Action<string> writeDraft, Func<bool> readBusy, Action<bool> writeBusy,
        Func<AiConversationMessage?> readAnswer, Action<AiConversationMessage?> writeAnswer,
        Func<AiEvidenceReference?> readReference, Action<AiEvidenceReference?> writeReference,
        Func<string> readStatus, Action<string> writeStatus, Func<string> readProgress, Action<string> writeProgress,
        string draftProperty, string statusProperty,
        Func<AiConversationDraftMetadata> readMetadata, Action<AiConversationDraftMetadata> writeMetadata,
        string? progressProperty)
    {
        _entries = entries; _conversationId = conversationId; _entry = entry;
        _presenter = presenter; _messages = messages; _references = references;
        _readDraft = readDraft; _writeDraft = writeDraft; _readBusy = readBusy; _writeBusy = writeBusy;
        _readAnswer = readAnswer; _writeAnswer = writeAnswer;
        _readReference = readReference; _writeReference = writeReference;
        _readStatus = readStatus; _writeStatus = writeStatus;
        _readProgress = readProgress; _writeProgress = writeProgress;
        _draftProperty = draftProperty; _statusProperty = statusProperty; _progressProperty = progressProperty;
        _readMetadata = readMetadata; _writeMetadata = writeMetadata;
        _presenter.PropertyChanged += PresenterChanged;
        _messages.CollectionChanged += MessagesChanged;
        _references.CollectionChanged += ReferencesChanged;
        _entry.Changed += EntryChanged;
        if (_entry.HasPresentation) Apply();
        else PublishAll();
    }

    internal bool IsExecuting => _entry.Execution is not null;
    internal bool HasOtherOwners { get { lock (_entries.Gate) return _entry.Owners > 1; } }
    internal bool IsExecutingWith(CancellationTokenSource cancellation) =>
        ReferenceEquals(_entry.Execution, cancellation) && !cancellation.IsCancellationRequested;

    internal void PublishMessages(IReadOnlyList<AiConversationMessage> messages, string? status = null)
    {
        // The initiating view may have been closed. Its execution claim still owns this entry
        // while another presenter lease observes the saved conversation.
        _entry.Messages = messages.ToArray();
        _entry.AnswerId = messages.LastOrDefault(message => message.Role == "assistant")?.Id;
        if (status is not null) _entry.Status = status;
        _entry.Notify();
    }

    internal void PublishProgress(string progress)
    {
        _entry.Progress = progress;
        _entry.Notify();
    }

    internal void PublishStatus(string status)
    {
        _entry.Status = status;
        _entry.Notify();
    }

    internal void PublishCompletion(string destination, bool clearDraft, bool clearRecovery)
    {
        _entry.Metadata = _entry.Metadata with
        {
            LastSubmissionDestination = destination,
            AnalystInstructions = clearDraft ? string.Empty : _entry.Metadata.AnalystInstructions,
            RecoveryMessageId = clearRecovery ? null : _entry.Metadata.RecoveryMessageId
        };
        if (clearDraft) _entry.Draft = string.Empty;
        _entry.Notify();
    }

    internal bool TryBeginExecution(CancellationTokenSource cancellation)
    {
        lock (_entry)
        {
            if (_disposed || _entry.Execution is not null) return false;
            _entry.Execution = cancellation;
            _entry.Busy = true;
        }
        _entry.Notify();
        return true;
    }

    internal void EndExecution(CancellationTokenSource cancellation)
    {
        lock (_entry)
        {
            if (!ReferenceEquals(_entry.Execution, cancellation)) return;
            _entry.Execution = null;
            _entry.Busy = false;
        }
        _entry.Notify();
    }

    internal void CancelExecution() => _entry.Execution?.Cancel();

    internal void PublishRecoveryMessageId(string? id)
    {
        if (_disposed || _applying) return;
        _entry.Metadata = _readMetadata() with { RecoveryMessageId = id };
        NotifyOtherPresenters();
    }

    private void PresenterChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (_disposed || _applying) return;
        var name = args.PropertyName;
        if (name != _draftProperty && name != "SelectedMessage" &&
            name != "SelectedReference" && name != _statusProperty && name != _progressProperty &&
            name != "AnalystInstructions" && name != "LastSubmissionDestination" &&
            name != "EvidenceStatus") return;
        if (name == _draftProperty) _entry.Draft = _readDraft();
        else if (name == "SelectedMessage") _entry.AnswerId = _readAnswer()?.Id;
        else if (name == "SelectedReference") _entry.ReferenceKey = AiConversationLiveState.ReferenceIdentity(_readReference());
        else if (name == _statusProperty) _entry.Status = _readStatus();
        else if (name == _progressProperty) _entry.Progress = _readProgress();
        else if (name is "AnalystInstructions" or "LastSubmissionDestination" or "EvidenceStatus") _entry.Metadata = _readMetadata();
        NotifyOtherPresenters();
    }

    private void MessagesChanged(object? sender, NotifyCollectionChangedEventArgs args)
    {
        if (_disposed || _applying) return;
        _entry.Messages = _messages.ToArray();
        NotifyOtherPresenters();
    }

    private void ReferencesChanged(object? sender, NotifyCollectionChangedEventArgs args)
    {
        if (_disposed || _applying) return;
        _entry.References = _references.ToArray();
        NotifyOtherPresenters();
    }

    private void PublishAll()
    {
        _entry.Draft = _readDraft(); _entry.Status = _readStatus(); _entry.Progress = _readProgress();
        _entry.Metadata = _readMetadata();
        _entry.Busy = _entry.Execution is not null;
        _entry.Messages = _messages.ToArray(); _entry.References = _references.ToArray();
        _entry.AnswerId = _readAnswer()?.Id;
        _entry.ReferenceKey = AiConversationLiveState.ReferenceIdentity(_readReference());
        _entry.HasPresentation = true;
        _entry.Notify();
    }

    private void NotifyOtherPresenters()
    {
        _publishing = true;
        try { _entry.Notify(); }
        finally { _publishing = false; }
    }

    private void EntryChanged()
    {
        if (_disposed || _applying || _publishing) return;
        if (_context is { } context && !ReferenceEquals(SynchronizationContext.Current, context))
            context.Post(_ => Apply(), null);
        else Apply();
    }

    private void Apply()
    {
        if (_disposed || _applying) return;
        _applying = true;
        try
        {
            if (_readDraft() != _entry.Draft) _writeDraft(_entry.Draft);
            if (_readBusy() != _entry.Busy) _writeBusy(_entry.Busy);
            if (_readStatus() != _entry.Status) _writeStatus(_entry.Status);
            if (_readMetadata() != _entry.Metadata) _writeMetadata(_entry.Metadata);
            if (_progressProperty is not null && _readProgress() != _entry.Progress) _writeProgress(_entry.Progress);
            if (!_messages.SequenceEqual(_entry.Messages))
            {
                _messages.Clear();
                foreach (var message in _entry.Messages) _messages.Add(message);
            }
            var answer = _entry.AnswerId is null ? null : _messages.FirstOrDefault(m => m.Id == _entry.AnswerId);
            if (_readAnswer()?.Id != answer?.Id) _writeAnswer(answer);
            if (!_references.SequenceEqual(_entry.References))
            {
                _references.Clear();
                foreach (var entryReference in _entry.References) _references.Add(entryReference);
            }
            var reference = _entry.ReferenceKey is null ? null :
                _references.FirstOrDefault(r => AiConversationLiveState.ReferenceIdentity(r) == _entry.ReferenceKey);
            if (AiConversationLiveState.ReferenceIdentity(_readReference()) !=
                AiConversationLiveState.ReferenceIdentity(reference))
                _writeReference(reference);
        }
        finally { _applying = false; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _presenter.PropertyChanged -= PresenterChanged;
        _messages.CollectionChanged -= MessagesChanged;
        _references.CollectionChanged -= ReferencesChanged;
        _entry.Changed -= EntryChanged;
        lock (_entries.Gate)
        {
            if (--_entry.Owners != 0) return;
            _entry.Execution?.Cancel();
            _entries.Items.Remove(_conversationId);
        }
    }
}
