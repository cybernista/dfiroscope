using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Stores normalized process events in a bounded in-memory buffer.
/// </summary>
public class ProcessEventStore
{
    private readonly List<ProcessEventInfo> _events = new();
    private readonly object _lock = new();
    private readonly bool _retainEvents;
    private readonly EventCollectionStats _stats = new EventCollectionStats
    {
        StatusMessage = "Process event collection is ready."
    };

    private EventCollectionOptions _options;
    private long _nextSequenceId = 1;

    public event EventHandler<ProcessEventsAddedEventArgs>? EventsAdded;
    public event EventHandler<EventCollectionStats>? StatsChanged;

    public ProcessEventStore(
        EventCollectionOptions options,
        bool retainEvents = true)
    {
        _options = options;
        _retainEvents = retainEvents;
        _options.Validate();

        if (!_retainEvents)
        {
            _stats.StatusMessage = "Forwarding normalized events to the active evidence publisher.";
        }
    }

    /// <summary>
    /// Adds a single normalized event to the store.
    /// </summary>
    public void AddEvent(ProcessEventInfo processEvent)
    {
        AddEvents(new[] { processEvent });
    }

    /// <summary>
    /// Adds multiple normalized events to the store.
    /// </summary>
    public void AddEvents(IEnumerable<ProcessEventInfo> events)
    {
        var addedEvents = new List<ProcessEventInfo>();
        EventCollectionStats statsSnapshot;

        lock (_lock)
        {
            foreach (var processEvent in events)
            {
                processEvent.SequenceId = _nextSequenceId++;

                if (_retainEvents)
                {
                    processEvent.EstimatedSizeBytes = EstimateEventSize(processEvent);

                    if (!_options.OverwriteMemoryWhenFull &&
                        _stats.CurrentMemoryBytes + processEvent.EstimatedSizeBytes > _options.MemoryCapBytes)
                    {
                        _stats.TotalDropped++;
                        _stats.IsCollectionPaused = true;
                        _stats.StatusMessage = "Process event collection paused because the memory cap was reached.";
                        continue;
                    }

                    _events.Add(processEvent);
                    _stats.CurrentMemoryBytes += processEvent.EstimatedSizeBytes;

                    EvictExpiredEvents();
                    EvictUntilUnderLimit();
                }

                _stats.TotalCollected++;
                addedEvents.Add(processEvent);
            }

            _stats.InMemoryEventCount = _events.Count;

            if (!_stats.IsCollectionPaused)
            {
                _stats.StatusMessage = _retainEvents
                    ? "Collecting live process events."
                    : "Forwarding normalized events to the active evidence publisher.";
            }

            statsSnapshot = CloneStats();
        }

        if (addedEvents.Count > 0)
        {
            EventsAdded?.Invoke(this, new ProcessEventsAddedEventArgs(addedEvents));
        }

        StatsChanged?.Invoke(this, statsSnapshot);
    }

    /// <summary>
    /// Gets events for a specific process instance.
    /// </summary>
    public IReadOnlyList<ProcessEventInfo> GetEventsForProcess(string processKey, int maxCount = 5000)
    {
        if (maxCount <= 0 || string.IsNullOrEmpty(processKey))
        {
            return Array.Empty<ProcessEventInfo>();
        }

        lock (_lock)
        {
            var matches = new List<ProcessEventInfo>(Math.Min(maxCount, _events.Count));
            for (var index = _events.Count - 1; index >= 0 && matches.Count < maxCount; index--)
            {
                var processEvent = _events[index];
                if (processEvent.ProcessKey == processKey)
                {
                    matches.Add(processEvent);
                }
            }

            matches.Reverse();
            return matches;
        }
    }

    /// <summary>
    /// Counts events currently retained for a specific process instance.
    /// </summary>
    public int CountEventsForProcess(string processKey)
    {
        lock (_lock)
        {
            return _events.Count(e => e.ProcessKey == processKey);
        }
    }

    /// <summary>
    /// Gets a snapshot of the current collection stats.
    /// </summary>
    public EventCollectionStats GetStats()
    {
        lock (_lock)
        {
            return CloneStats();
        }
    }

    /// <summary>
    /// Updates store options.
    /// </summary>
    public void SetOptions(EventCollectionOptions options)
    {
        options.Validate();

        EventCollectionStats statsSnapshot;
        lock (_lock)
        {
            _options = options;
            if (_retainEvents)
            {
                EvictExpiredEvents();
                EvictUntilUnderLimit();
            }

            _stats.InMemoryEventCount = _events.Count;

            if (_stats.IsCollectionPaused && (!_retainEvents || _stats.CurrentMemoryBytes < _options.MemoryCapBytes))
            {
                _stats.IsCollectionPaused = false;
                _stats.StatusMessage = _retainEvents
                    ? "Collecting live process events."
                    : "Forwarding normalized events to the active evidence publisher.";
            }

            statsSnapshot = CloneStats();
        }

        StatsChanged?.Invoke(this, statsSnapshot);
    }

    private void EvictUntilUnderLimit()
    {
        if (_stats.CurrentMemoryBytes <= _options.MemoryCapBytes || _events.Count == 0)
        {
            return;
        }

        var bytesToFree = _stats.CurrentMemoryBytes - _options.MemoryCapBytes;
        long freedBytes = 0;
        var removeCount = 0;
        while (removeCount < _events.Count && freedBytes < bytesToFree)
        {
            freedBytes += _events[removeCount].EstimatedSizeBytes;
            removeCount++;
        }

        if (removeCount > 0)
        {
            _events.RemoveRange(0, removeCount);
            _stats.CurrentMemoryBytes -= freedBytes;
        }

        if (_stats.CurrentMemoryBytes < 0)
        {
            _stats.CurrentMemoryBytes = 0;
        }
    }

    private void EvictExpiredEvents()
    {
        var cutoffUtc = DateTime.UtcNow.Subtract(_options.RetentionPeriod);
        long freedBytes = 0;
        var removeCount = 0;
        while (removeCount < _events.Count && _events[removeCount].TimestampUtc < cutoffUtc)
        {
            freedBytes += _events[removeCount].EstimatedSizeBytes;
            removeCount++;
        }

        if (removeCount > 0)
        {
            _events.RemoveRange(0, removeCount);
            _stats.CurrentMemoryBytes -= freedBytes;
        }

        if (_stats.CurrentMemoryBytes < 0)
        {
            _stats.CurrentMemoryBytes = 0;
        }
    }

    private static long EstimateEventSize(ProcessEventInfo processEvent)
    {
        long size = 256;
        size += (processEvent.ProcessKey.Length
            + processEvent.ProcessName.Length
            + processEvent.Target.Length
            + processEvent.Summary.Length
            + processEvent.Details.Length
            + processEvent.RiskFlags.Length) * sizeof(char);
        return size;
    }

    private EventCollectionStats CloneStats()
    {
        return new EventCollectionStats
        {
            CurrentMemoryBytes = _stats.CurrentMemoryBytes,
            InMemoryEventCount = _stats.InMemoryEventCount,
            TotalCollected = _stats.TotalCollected,
            TotalDropped = _stats.TotalDropped,
            IsCollectionPaused = _stats.IsCollectionPaused,
            StatusMessage = _stats.StatusMessage
        };
    }
}

/// <summary>
/// Event args for newly added process events.
/// </summary>
public class ProcessEventsAddedEventArgs : EventArgs
{
    public IReadOnlyList<ProcessEventInfo> Events { get; }

    public ProcessEventsAddedEventArgs(IReadOnlyList<ProcessEventInfo> events)
    {
        Events = events;
    }
}
