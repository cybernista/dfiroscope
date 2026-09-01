using System;
using System.Collections.Generic;
using System.Linq;

namespace ProcInsider.ViewModels;

/// <summary>
/// Cycle-safe in-memory compatibility graph for Explorer process descendant badges.
/// SQLite-backed Explorer projection remains the primary path.
/// </summary>
internal sealed class ExplorerProcessHierarchy
{
    private readonly Dictionary<string, List<ProcessRowViewModel>> _childrenByParentKey =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _parentKeyByChildKey =
        new(StringComparer.Ordinal);

    internal ExplorerProcessHierarchy(IEnumerable<ProcessRowViewModel> processes)
    {
        var rows = processes.ToList();
        foreach (var child in rows)
        {
            var parent = ResolveParent(child, rows);
            if (parent == null)
            {
                continue;
            }

            _parentKeyByChildKey[child.ProcessKey] = parent.ProcessKey;
            if (!_childrenByParentKey.TryGetValue(parent.ProcessKey, out var children))
            {
                children = [];
                _childrenByParentKey[parent.ProcessKey] = children;
            }

            children.Add(child);
        }

        foreach (var children in _childrenByParentKey.Values)
        {
            children.Sort(CompareProcesses);
        }
    }

    internal bool HasResolvableParent(ProcessRowViewModel process)
        => _parentKeyByChildKey.ContainsKey(process.ProcessKey);

    internal bool IsImmediateChildOf(ProcessRowViewModel process, string parentProcessKey)
    {
        return !string.IsNullOrWhiteSpace(parentProcessKey) &&
               _parentKeyByChildKey.TryGetValue(process.ProcessKey, out var resolvedParentKey) &&
               string.Equals(resolvedParentKey, parentProcessKey, StringComparison.Ordinal);
    }

    internal int CountDescendants(ProcessRowViewModel process)
    {
        var rootKey = process.ProcessKey;
        if (string.IsNullOrWhiteSpace(rootKey))
        {
            return 0;
        }

        var visited = new HashSet<string>(StringComparer.Ordinal) { rootKey };
        var pending = new Stack<string>();
        pending.Push(rootKey);

        while (pending.Count > 0)
        {
            var parentKey = pending.Pop();
            if (!_childrenByParentKey.TryGetValue(parentKey, out var children))
            {
                continue;
            }

            foreach (var child in children)
            {
                if (visited.Add(child.ProcessKey))
                {
                    pending.Push(child.ProcessKey);
                }
            }
        }

        return visited.Count - 1;
    }

    private static ProcessRowViewModel? ResolveParent(
        ProcessRowViewModel child,
        IReadOnlyCollection<ProcessRowViewModel> rows)
    {
        var parentKey = child.ProcessInfo.ParentProcessKey;
        if (!string.IsNullOrWhiteSpace(parentKey))
        {
            return rows
                .Where(parent => string.Equals(parent.ProcessKey, parentKey, StringComparison.Ordinal))
                .Where(parent => !ReferenceEquals(parent, child))
                .Where(parent => HasSameEvidenceIdentity(child, parent))
                .OrderBy(parent => parent, ProcessComparer.Instance)
                .FirstOrDefault();
        }

        var parentEntityId = child.ProcessInfo.ParentProcessEntityId;
        if (!string.IsNullOrWhiteSpace(parentEntityId))
        {
            return rows
                .Where(parent => string.Equals(
                    parent.ProcessInfo.ProcessEntityId,
                    parentEntityId,
                    StringComparison.Ordinal))
                .Where(parent => !ReferenceEquals(parent, child))
                .Where(parent => HasSameEvidenceIdentity(child, parent))
                .OrderBy(parent => parent, ProcessComparer.Instance)
                .FirstOrDefault();
        }

        if (child.ProcessInfo.ParentProcessId <= 0)
        {
            return null;
        }

        return rows
            .Where(parent => parent.ProcessId == child.ProcessInfo.ParentProcessId)
            .Where(parent => !ReferenceEquals(parent, child))
            .Where(parent => HasSameEvidenceIdentity(child, parent))
            .Where(parent => IsPlausibleParentStart(child, parent))
            .OrderByDescending(parent => parent.ProcessInfo.StartTime ?? DateTime.MinValue)
            .ThenBy(parent => parent.ProcessKey, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static bool HasSameEvidenceIdentity(
        ProcessRowViewModel child,
        ProcessRowViewModel parent)
    {
        return string.Equals(child.ProcessInfo.CaseId, parent.ProcessInfo.CaseId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.EvidenceSessionId, parent.ProcessInfo.EvidenceSessionId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.CaptureId, parent.ProcessInfo.CaptureId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.SourceIdentityId, parent.ProcessInfo.SourceIdentityId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.HostId, parent.ProcessInfo.HostId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.ExecutionRootId, parent.ProcessInfo.ExecutionRootId, StringComparison.Ordinal);
    }

    private static bool IsPlausibleParentStart(
        ProcessRowViewModel child,
        ProcessRowViewModel parent)
    {
        return child.ProcessInfo.StartTime == null ||
               parent.ProcessInfo.StartTime == null ||
               child.ProcessInfo.StartTime >= parent.ProcessInfo.StartTime;
    }

    private static int CompareProcesses(ProcessRowViewModel left, ProcessRowViewModel right)
    {
        var startComparison = Nullable.Compare(left.ProcessInfo.StartTime, right.ProcessInfo.StartTime);
        return startComparison != 0
            ? startComparison
            : StringComparer.Ordinal.Compare(left.ProcessKey, right.ProcessKey);
    }

    private sealed class ProcessComparer : IComparer<ProcessRowViewModel>
    {
        internal static ProcessComparer Instance { get; } = new();

        public int Compare(ProcessRowViewModel? left, ProcessRowViewModel? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left == null)
            {
                return -1;
            }

            return right == null ? 1 : CompareProcesses(left, right);
        }
    }
}
