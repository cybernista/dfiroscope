using System;
using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Versioned, deterministic process-observation precedence policy. All incremental
/// projection and rebuild paths call this class; precedence must not be duplicated in SQL.
/// </summary>
public static class ProcessProjectionPolicy
{
    public const string Version = "process-projection-v1";

    public static ProcessProjectionResolution Resolve(IReadOnlyList<ProcessObservation> observations)
    {
        if (observations.Count == 0)
        {
            throw new ArgumentException("At least one process observation is required.", nameof(observations));
        }

        var ordered = new ProcessObservation[observations.Count];
        for (var i = 0; i < observations.Count; i++)
        {
            ordered[i] = observations[i];
        }
        Array.Sort(ordered, static (left, right) =>
            StringComparer.Ordinal.Compare(left.ObservationId, right.ObservationId));
        var seed = ordered[0].Fields;
        var projected = Clone(seed);
        var winners = new List<ProcessProjectionFieldWinner>();
        var conflicts = 0;
        var latest = ordered[0];
        var lifecycle = ordered[0];
        var firstObservedUtc = ordered[0].ObservedUtc;
        var lastObservedUtc = ordered[0].ObservedUtc;
        for (var i = 1; i < ordered.Length; i++)
        {
            var observation = ordered[i];
            if (IsBetterObservedCandidate(observation, latest))
            {
                latest = observation;
            }
            if (IsBetterLifecycleCandidate(observation, lifecycle))
            {
                lifecycle = observation;
            }
            if (observation.ObservedUtc < firstObservedUtc)
            {
                firstObservedUtc = observation.ObservedUtc;
            }
            if (observation.ObservedUtc > lastObservedUtc)
            {
                lastObservedUtc = observation.ObservedUtc;
            }
        }

        projected.ProcessEntityId = observations[0].ProcessEntityId;
        projected.ProcessKey = PickString("ProcessKey", static o => o.Fields.ProcessKey);
        projected.ProcessGuid = PickString("ProcessGuid", static o => o.Fields.ProcessGuid);
        projected.ProcessName = PickString("ProcessName", static o => o.Fields.ProcessName);
        projected.ProcessPath = PickString("ProcessPath", static o => o.Fields.ProcessPath);
        projected.CommandLine = PickString("CommandLine", static o => o.Fields.CommandLine);
        projected.UserName = PickString("UserName", static o => o.Fields.UserName);
        projected.ParentProcessKey = PickString("ParentProcessKey", static o => o.Fields.ParentProcessKey);
        projected.ParentProcessEntityId = PickString("ParentProcessEntityId", static o => o.Fields.ParentProcessEntityId);
        projected.ParentProcessName = PickString("ParentProcessName", static o => o.Fields.ParentProcessName);
        projected.Architecture = PickString("Architecture", static o => o.Fields.Architecture);
        projected.CompanyName = PickString("CompanyName", static o => o.Fields.CompanyName);
        projected.FileDescription = PickString("FileDescription", static o => o.Fields.FileDescription);
        projected.Sha256Hash = PickString("Sha256Hash", static o => o.Fields.Sha256Hash);

        projected.ProcessId = PickValue("ProcessId", static o => o.Fields.ProcessId, static value => value > 0);
        projected.ParentProcessId = PickValue("ParentProcessId", static o => o.Fields.ParentProcessId, static value => value > 0);
        projected.SessionId = PickValue("SessionId", static o => o.Fields.SessionId, static value => value > 0);
        projected.StartTimeUtc = PickValue<DateTime?>("StartTimeUtc", static o => o.Fields.StartTimeUtc, static value => value.HasValue);
        projected.EndTimeUtc = PickValue<DateTime?>("EndTimeUtc", static o => o.Fields.EndTimeUtc, static value => value.HasValue);

        projected.Status = lifecycle.StatusAssertion;
        AddWinner("Status", lifecycle, LifecycleRank(lifecycle), "explicit lifecycle rank, then observed time");
        if (projected.Status == ProcessStatus.Exited && !projected.EndTimeUtc.HasValue)
        {
            projected.EndTimeUtc = lifecycle.ValidToUtc ?? lifecycle.ObservedUtc;
        }

        projected.FirstObservedUtc = firstObservedUtc;
        projected.LastObservedUtc = lastObservedUtc;
        projected.LastSource = latest.Fields.LastSource;
        projected.SourceIdentityId = latest.Fields.SourceIdentityId;
        projected.CaptureId = latest.Fields.CaptureId;
        projected.CaseId = latest.Fields.CaseId;
        projected.EvidenceSessionId = latest.Fields.EvidenceSessionId;
        projected.HostId = latest.Fields.HostId;
        projected.ExecutionRootId = latest.Fields.ExecutionRootId;
        projected.CpuUsage = latest.Fields.CpuUsage;
        projected.MemoryUsageBytes = latest.Fields.MemoryUsageBytes;
        projected.TreeDepth = latest.Fields.TreeDepth;
        projected.ModuleCaptureStatus = latest.Fields.ModuleCaptureStatus;
        projected.ModuleCount = latest.Fields.ModuleCount;
        projected.ModuleLastCapturedUtc = latest.Fields.ModuleLastCapturedUtc;
        projected.ModuleCaptureError = latest.Fields.ModuleCaptureError;
        projected.HandleCaptureStatus = latest.Fields.HandleCaptureStatus;
        projected.HandleCount = latest.Fields.HandleCount;
        projected.HandleLastCapturedUtc = latest.Fields.HandleLastCapturedUtc;
        projected.HandleCaptureError = latest.Fields.HandleCaptureError;

        return new ProcessProjectionResolution(projected, winners, conflicts);

        string PickString(string field, Func<ProcessObservation, string> selector)
        {
            ProcessObservation? winner = null;
            var winnerScore = 0;
            string? firstDistinctValue = null;
            HashSet<string>? distinctValues = null;
            var distinctCount = 0;
            foreach (var observation in ordered)
            {
                var value = selector(observation);
                if (!IsKnown(value) || StateQuality(observation, field) <= 0)
                {
                    continue;
                }

                TrackDistinctString(value);
                var score = CandidateScore(observation, field);
                if (winner == null || IsBetterRankedCandidate(observation, score, winner, winnerScore))
                {
                    winner = observation;
                    winnerScore = score;
                }
            }

            if (winner == null)
            {
                return selector(latest);
            }

            conflicts += Math.Max(0, distinctCount - 1);
            var selectedValue = selector(winner);
            AddWinner(field, winner, winnerScore, "availability > identity confidence > source authority > observed time");
            return selectedValue;

            void TrackDistinctString(string value)
            {
                if (distinctCount == 0)
                {
                    firstDistinctValue = value;
                    distinctCount = 1;
                    return;
                }
                if (StringComparer.OrdinalIgnoreCase.Equals(firstDistinctValue, value))
                {
                    return;
                }

                distinctValues ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase) { firstDistinctValue! };
                if (distinctValues.Add(value))
                {
                    distinctCount++;
                }
            }
        }

        T PickValue<T>(string field, Func<ProcessObservation, T> selector, Func<T, bool> supplied)
        {
            ProcessObservation? winner = null;
            var winnerScore = 0;
            var firstDistinctValue = default(T);
            HashSet<T>? distinctValues = null;
            var distinctCount = 0;
            foreach (var observation in ordered)
            {
                var value = selector(observation);
                if (!supplied(value) || StateQuality(observation, field) <= 0)
                {
                    continue;
                }

                TrackDistinctValue(value);
                var score = CandidateScore(observation, field);
                if (winner == null || IsBetterRankedCandidate(observation, score, winner, winnerScore))
                {
                    winner = observation;
                    winnerScore = score;
                }
            }

            if (winner == null)
            {
                return selector(latest);
            }

            conflicts += Math.Max(0, distinctCount - 1);
            var selectedValue = selector(winner);
            AddWinner(field, winner, winnerScore, "supplied value > identity confidence > source authority > observed time");
            return selectedValue;

            void TrackDistinctValue(T value)
            {
                if (distinctCount == 0)
                {
                    firstDistinctValue = value;
                    distinctCount = 1;
                    return;
                }
                if (EqualityComparer<T>.Default.Equals(firstDistinctValue, value))
                {
                    return;
                }

                distinctValues ??= new HashSet<T> { firstDistinctValue! };
                if (distinctValues.Add(value))
                {
                    distinctCount++;
                }
            }
        }

        void AddWinner(string field, ProcessObservation observation, int quality, string reason)
            => winners.Add(new ProcessProjectionFieldWinner(field, observation.ObservationId, observation.SourceRunId, quality, reason));
    }

    private static bool IsBetterRankedCandidate(
        ProcessObservation candidate,
        int candidateScore,
        ProcessObservation current,
        int currentScore)
        => candidateScore > currentScore ||
           (candidateScore == currentScore && IsBetterObservedCandidate(candidate, current));

    private static bool IsBetterObservedCandidate(ProcessObservation candidate, ProcessObservation current)
        => candidate.ObservedUtc > current.ObservedUtc ||
           (candidate.ObservedUtc == current.ObservedUtc &&
            StringComparer.Ordinal.Compare(candidate.ObservationId, current.ObservationId) < 0);

    private static bool IsBetterLifecycleCandidate(ProcessObservation candidate, ProcessObservation current)
    {
        var candidateRank = LifecycleRank(candidate);
        var currentRank = LifecycleRank(current);
        return candidateRank > currentRank ||
               (candidateRank == currentRank && IsBetterObservedCandidate(candidate, current));
    }

    private static int CandidateScore(ProcessObservation observation, string field)
        => StateQuality(observation, field) * 100000 +
           (int)Math.Round(Math.Clamp(observation.CorrelationConfidence, 0, 1) * 1000) * 100 +
           SourceAuthority(observation.Fields.LastSource, field);

    private static int StateQuality(ProcessObservation observation, string field)
        => observation.FieldStates.TryGetValue(field, out var state) ? state switch
        {
            ProcessObservationValueState.Available => 4,
            ProcessObservationValueState.Unavailable => 1,
            ProcessObservationValueState.AccessDenied => 0,
            _ => 0
        } : 4;

    private static int SourceAuthority(string source, string field)
    {
        if ((field is "CompanyName" or "FileDescription" or "Sha256Hash") && source.Contains("Enrichment", StringComparison.OrdinalIgnoreCase)) return 500;
        if (source.Contains("Sysmon", StringComparison.OrdinalIgnoreCase)) return 450;
        if (source.Contains("Runtime", StringComparison.OrdinalIgnoreCase) || source.Contains("Tracker", StringComparison.OrdinalIgnoreCase)) return 425;
        if (source.Contains("WMI", StringComparison.OrdinalIgnoreCase)) return 400;
        if (source.Contains("Procmon", StringComparison.OrdinalIgnoreCase)) return 325;
        if (source.Contains("Volatility", StringComparison.OrdinalIgnoreCase) || source.Contains("Memory", StringComparison.OrdinalIgnoreCase)) return 275;
        return 200;
    }

    private static int LifecycleRank(ProcessObservation observation) => observation.StatusAssertion switch
    {
        ProcessStatus.Exited when observation.ValidToUtc.HasValue || observation.Fields.EndTimeUtc.HasValue => 1000,
        ProcessStatus.Exited => 900,
        ProcessStatus.NotFound => 600,
        ProcessStatus.Running => 500,
        _ => 0
    };

    public static bool IsKnown(string? value)
    {
        value = value?.Trim();
        return !string.IsNullOrEmpty(value) &&
               !value.Equals("<not available>", StringComparison.OrdinalIgnoreCase) &&
               !value.Equals("<unknown>", StringComparison.OrdinalIgnoreCase) &&
               !value.Contains("access denied", StringComparison.OrdinalIgnoreCase);
    }

    private static ProcessRecord Clone(ProcessRecord value) => new()
    {
        ProcessEntityId = value.ProcessEntityId, CaseId = value.CaseId, EvidenceSessionId = value.EvidenceSessionId,
        CaptureId = value.CaptureId, SourceIdentityId = value.SourceIdentityId, HostId = value.HostId,
        ExecutionRootId = value.ExecutionRootId, ProcessKey = value.ProcessKey, ProcessId = value.ProcessId,
        ProcessGuid = value.ProcessGuid, StartTimeUtc = value.StartTimeUtc, EndTimeUtc = value.EndTimeUtc,
        Status = value.Status, ModuleCaptureStatus = value.ModuleCaptureStatus, ModuleCount = value.ModuleCount,
        ModuleLastCapturedUtc = value.ModuleLastCapturedUtc, ModuleCaptureError = value.ModuleCaptureError,
        HandleCaptureStatus = value.HandleCaptureStatus, HandleCount = value.HandleCount,
        HandleLastCapturedUtc = value.HandleLastCapturedUtc, HandleCaptureError = value.HandleCaptureError,
        ParentProcessId = value.ParentProcessId, ParentProcessKey = value.ParentProcessKey,
        ParentProcessEntityId = value.ParentProcessEntityId, ParentProcessName = value.ParentProcessName,
        ProcessName = value.ProcessName, ProcessPath = value.ProcessPath, CommandLine = value.CommandLine,
        UserName = value.UserName, SessionId = value.SessionId, Architecture = value.Architecture,
        CpuUsage = value.CpuUsage, MemoryUsageBytes = value.MemoryUsageBytes, CompanyName = value.CompanyName,
        FileDescription = value.FileDescription, Sha256Hash = value.Sha256Hash, TreeDepth = value.TreeDepth,
        FirstObservedUtc = value.FirstObservedUtc, LastObservedUtc = value.LastObservedUtc, LastSource = value.LastSource
    };
}
