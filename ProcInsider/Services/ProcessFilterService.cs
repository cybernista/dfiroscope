using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Provides filtering and sorting logic for process lists.
/// </summary>
public class ProcessFilterService
{
    /// <summary>
    /// Filters processes based on column-specific filters.
    /// </summary>
    /// <param name="processes">The list of processes to filter.</param>
    /// <param name="filters">Dictionary of column name to filter text.</param>
    /// <returns>Filtered list of processes.</returns>
    public List<ProcessInfo> ApplyFilters(List<ProcessInfo> processes, Dictionary<string, string> filters)
    {
        if (filters.Count == 0 || filters.Values.All(string.IsNullOrWhiteSpace))
            return processes;

        var filtered = new HashSet<ProcessInfo>();
        var matchedPids = new HashSet<int>();

        foreach (var proc in processes)
        {
            if (MatchesAllFilters(proc, filters))
            {
                filtered.Add(proc);
                matchedPids.Add(proc.ProcessId);
            }
        }

        // Include parent processes for context when filtering
        var hasRealFilters = filters.Values.Any(f => !string.IsNullOrWhiteSpace(f));
        if (hasRealFilters)
        {
            var additionalParents = new HashSet<ProcessInfo>();
            foreach (var proc in filtered)
            {
                AddParentChain(proc, processes, additionalParents, matchedPids);
            }
            foreach (var parent in additionalParents)
            {
                filtered.Add(parent);
            }
        }

        return filtered.ToList();
    }

    /// <summary>
    /// Adds parent processes to the result set for context.
    /// </summary>
    private void AddParentChain(ProcessInfo proc, List<ProcessInfo> allProcesses, 
        HashSet<ProcessInfo> additionalParents, HashSet<int> alreadyIncluded)
    {
        var visitedProcessKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            proc.GetUniqueKey()
        };

        var parent = ResolveParentProcess(proc, allProcesses);
        while (parent != null)
        {
            var parentKey = parent.GetUniqueKey();
            if (!visitedProcessKeys.Add(parentKey) || alreadyIncluded.Contains(parent.ProcessId))
            {
                break;
            }

            additionalParents.Add(parent);
            alreadyIncluded.Add(parent.ProcessId);
            parent = ResolveParentProcess(parent, allProcesses);
        }
    }

    private static ProcessInfo? ResolveParentProcess(ProcessInfo process, List<ProcessInfo> allProcesses)
    {
        if (process.ParentProcessId <= 0)
        {
            return null;
        }

        var processKey = process.GetUniqueKey();
        var candidates = allProcesses
            .Where(p =>
                p.ProcessId == process.ParentProcessId &&
                !string.Equals(p.GetUniqueKey(), processKey, StringComparison.Ordinal))
            .ToList();

        if (candidates.Count == 0)
        {
            return null;
        }

        var childObservedTime = process.StartTime ?? process.EndTime;
        if (childObservedTime.HasValue)
        {
            var matchingCandidate = candidates
                .Where(p => (p.StartTime ?? DateTime.MinValue) <= childObservedTime.Value)
                .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
                .ThenBy(p => p.Status == ProcessStatus.Running ? 0 : 1)
                .FirstOrDefault();

            if (matchingCandidate != null)
            {
                return matchingCandidate;
            }
        }

        return candidates
            .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
            .ThenBy(p => p.Status == ProcessStatus.Running ? 0 : 1)
            .FirstOrDefault();
    }

    /// <summary>
    /// Checks if a process matches all specified filters.
    /// </summary>
    private bool MatchesAllFilters(ProcessInfo proc, Dictionary<string, string> filters)
    {
        foreach (var filter in filters)
        {
            if (string.IsNullOrWhiteSpace(filter.Value))
                continue;

            var value = GetColumnValue(proc, filter.Key);
            if (!value.Contains(filter.Value, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Gets the string value of a column for filtering.
    /// </summary>
    private string GetColumnValue(ProcessInfo proc, string columnName)
    {
        return columnName.ToLowerInvariant() switch
        {
            "processname" or "name" => proc.ProcessName,
            "pid" or "processid" => proc.ProcessId.ToString(),
            "parentpid" or "parentprocessid" => proc.ParentProcessId.ToString(),
            "parentprocessname" or "parentname" => proc.ParentProcessName,
            "processpath" or "path" => proc.ProcessPath,
            "commandline" => proc.CommandLine,
            "username" or "user" => proc.UserName,
            "sessionid" => proc.SessionId.ToString(),
            "architecture" or "arch" => proc.Architecture,
            "starttime" => proc.StartTime?.ToString() ?? "",
            "endtime" => proc.EndTime?.ToString() ?? "",
            "status" => proc.Status.ToString(),
            "cpuusage" or "cpu" => proc.CpuUsageFormatted,
            "memoryusage" or "memory" => proc.MemoryUsageFormatted,
            "companyname" or "company" => proc.CompanyName,
            "filedescription" or "description" => proc.FileDescription,
            "sha256hash" or "hash" or "sha256" => proc.Sha256Hash,
            _ => ""
        };
    }

    /// <summary>
    /// Sorts processes with tree-aware sorting for ProcessName column.
    /// </summary>
    /// <param name="processes">The list of processes to sort.</param>
    /// <param name="sortColumn">The column to sort by.</param>
    /// <param name="ascending">Whether to sort ascending.</param>
    /// <returns>Sorted list of processes.</returns>
    public List<ProcessInfo> SortProcesses(List<ProcessInfo> processes, string sortColumn, bool ascending)
    {
        // Special handling for Tree/ProcessName - preserve parent-child relationships.
        if (sortColumn.Equals("ProcessName", StringComparison.OrdinalIgnoreCase) ||
            sortColumn.Equals("Name", StringComparison.OrdinalIgnoreCase) ||
            sortColumn.Equals("Tree", StringComparison.OrdinalIgnoreCase))
        {
            return SortProcessTree(processes, ascending);
        }

        // Standard sorting for other columns
        return sortColumn.ToLowerInvariant() switch
        {
            "pid" or "processid" => ascending 
                ? processes.OrderBy(p => p.ProcessId).ToList()
                : processes.OrderByDescending(p => p.ProcessId).ToList(),
            "parentpid" or "parentprocessid" => ascending
                ? processes.OrderBy(p => p.ParentProcessId).ToList()
                : processes.OrderByDescending(p => p.ParentProcessId).ToList(),
            "parentprocessname" or "parentname" => ascending
                ? processes.OrderBy(p => p.ParentProcessName).ToList()
                : processes.OrderByDescending(p => p.ParentProcessName).ToList(),
            "processpath" or "path" => ascending
                ? processes.OrderBy(p => p.ProcessPath).ToList()
                : processes.OrderByDescending(p => p.ProcessPath).ToList(),
            "commandline" => ascending
                ? processes.OrderBy(p => p.CommandLine).ToList()
                : processes.OrderByDescending(p => p.CommandLine).ToList(),
            "username" or "user" => ascending
                ? processes.OrderBy(p => p.UserName).ToList()
                : processes.OrderByDescending(p => p.UserName).ToList(),
            "sessionid" => ascending
                ? processes.OrderBy(p => p.SessionId).ToList()
                : processes.OrderByDescending(p => p.SessionId).ToList(),
            "architecture" or "arch" => ascending
                ? processes.OrderBy(p => p.Architecture).ToList()
                : processes.OrderByDescending(p => p.Architecture).ToList(),
            "starttime" => ascending
                ? processes.OrderBy(p => p.StartTime).ToList()
                : processes.OrderByDescending(p => p.StartTime).ToList(),
            "endtime" => ascending
                ? processes.OrderBy(p => p.EndTime).ToList()
                : processes.OrderByDescending(p => p.EndTime).ToList(),
            "status" => ascending
                ? processes.OrderBy(p => p.Status).ToList()
                : processes.OrderByDescending(p => p.Status).ToList(),
            "memoryusage" or "memory" => ascending
                ? processes.OrderBy(p => p.MemoryUsageBytes).ToList()
                : processes.OrderByDescending(p => p.MemoryUsageBytes).ToList(),
            "companyname" or "company" => ascending
                ? processes.OrderBy(p => p.CompanyName).ToList()
                : processes.OrderByDescending(p => p.CompanyName).ToList(),
            "filedescription" or "description" => ascending
                ? processes.OrderBy(p => p.FileDescription).ToList()
                : processes.OrderByDescending(p => p.FileDescription).ToList(),
            "sha256hash" or "hash" or "sha256" => ascending
                ? processes.OrderBy(p => p.Sha256Hash).ToList()
                : processes.OrderByDescending(p => p.Sha256Hash).ToList(),
            _ => processes
        };
    }

    /// <summary>
    /// Sorts processes as a tree, preserving parent-child relationships.
    /// Root processes are sorted, then each parent's children are sorted.
    /// </summary>
    private List<ProcessInfo> SortProcessTree(List<ProcessInfo> processes, bool ascending)
    {
        var result = new List<ProcessInfo>();
        var childrenByParentKey = new Dictionary<string, List<ProcessInfo>>(StringComparer.Ordinal);
        var roots = new List<ProcessInfo>();

        foreach (var proc in processes)
        {
            var parent = ResolveParentProcess(proc, processes);
            if (parent == null)
            {
                roots.Add(proc);
            }
            else
            {
                var parentKey = parent.GetUniqueKey();
                if (!childrenByParentKey.TryGetValue(parentKey, out var childList))
                {
                    childList = new List<ProcessInfo>();
                    childrenByParentKey[parentKey] = childList;
                }

                childList.Add(proc);
            }
        }

        roots = ascending
            ? roots.OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase).ToList()
            : roots.OrderByDescending(p => p.ProcessName, StringComparer.OrdinalIgnoreCase).ToList();

        var visited = new HashSet<string>(StringComparer.Ordinal);
        var activePath = new HashSet<string>(StringComparer.Ordinal);

        void AddWithChildren(ProcessInfo root)
        {
            var stack = new Stack<(ProcessInfo Process, bool Exit)>();
            stack.Push((root, false));

            while (stack.Count > 0)
            {
                var (proc, exit) = stack.Pop();
                var key = proc.GetUniqueKey();

                if (exit)
                {
                    activePath.Remove(key);
                    continue;
                }

                if (!activePath.Add(key))
                {
                    continue;
                }

                if (visited.Add(key))
                {
                    result.Add(proc);
                }

                stack.Push((proc, true));

                if (!childrenByParentKey.TryGetValue(key, out var children))
                {
                    continue;
                }

                var sortedChildren = ascending
                    ? children.OrderByDescending(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
                    : children.OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase);

                foreach (var child in sortedChildren)
                {
                    stack.Push((child, false));
                }
            }
        }

        foreach (var root in roots)
        {
            AddWithChildren(root);
        }

        foreach (var proc in processes)
        {
            if (!visited.Contains(proc.GetUniqueKey()))
            {
                AddWithChildren(proc);
            }
        }

        return result;
    }
}
