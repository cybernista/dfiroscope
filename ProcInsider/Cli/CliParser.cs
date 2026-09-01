using System.Globalization;
using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.Cli;

internal static class CliParser
{
    public const string UsageErrorCode = "InvalidCommandLine";

    internal sealed record Defaults(
        CliOutputMode OutputMode,
        string? SessionTarget,
        bool LockOutputMode = false);

    public static bool IsKnownEntry(IReadOnlyList<string> args)
    {
        if (args.Count == 0)
        {
            return false;
        }

        if (EnumerateCommandTokens(args).Any(IsKnownCommandToken))
        {
            return true;
        }

        var sawKnownOption = false;
        for (var index = 0; index < args.Count; index++)
        {
            var argument = args[index] ?? string.Empty;
            if (EqualsToken(argument, "--output") ||
                EqualsToken(argument, "--session") ||
                EqualsToken(argument, "--live-buffer-memory-mb") ||
                EqualsToken(argument, "--timeout-seconds") ||
                EqualsToken(argument, "--file") ||
                EqualsToken(argument, "--source") ||
                EqualsToken(argument, "--job-id") ||
                EqualsToken(argument, "--process-entity-id") ||
                EqualsToken(argument, "--process-key") ||
                EqualsToken(argument, "--pe-strings") ||
                EqualsToken(argument, "--kind") ||
                EqualsToken(argument, "--path") ||
                EqualsToken(argument, "--max-files") ||
                EqualsToken(argument, "--capture-id") ||
                EqualsToken(argument, "--pcap-path") ||
                EqualsToken(argument, "--zeek-path") ||
                EqualsToken(argument, "--wsl-distribution") ||
                EqualsToken(argument, "--wsl-command") ||
                EqualsToken(argument, "--procmon-path") ||
                EqualsToken(argument, "--input") ||
                EqualsToken(argument, "--max-rows") ||
                EqualsToken(argument, "--phase-duration-seconds") ||
                EqualsToken(argument, "--max-phase-count") ||
                EqualsToken(argument, "--initial-process-batch-size") ||
                EqualsToken(argument, "--initial-events-per-process") ||
                EqualsToken(argument, "--max-in-flight-batches") ||
                EqualsToken(argument, "--max-pending-writer-work-items") ||
                EqualsToken(argument, "--output-file-name") ||
                EqualsToken(argument, "--acquisition-timeout-seconds") ||
                EqualsToken(argument, "--image-path") ||
                EqualsToken(argument, "--display-name") ||
                EqualsToken(argument, "--host-name") ||
                EqualsToken(argument, "--os-build") ||
                EqualsToken(argument, "--acquisition-tool") ||
                EqualsToken(argument, "--acquisition-tool-version") ||
                EqualsToken(argument, "--acquisition-command-line") ||
                EqualsToken(argument, "--privilege-state") ||
                EqualsToken(argument, "--image-id") ||
                EqualsToken(argument, "--plugin") ||
                EqualsToken(argument, "--plugin-timeout-seconds"))
            {
                sawKnownOption = true;
                if (index + 1 < args.Count && !IsOption(args[index + 1]))
                {
                    index++;
                }

                continue;
            }

            if (EqualsToken(argument, "--no-prompt"))
            {
                sawKnownOption = true;
                continue;
            }

            if (EqualsToken(argument, "--yes"))
            {
                sawKnownOption = true;
                continue;
            }

            if (EqualsToken(argument, "--wait"))
            {
                sawKnownOption = true;
                continue;
            }

            if (EqualsToken(argument, "--accept-eula"))
            {
                sawKnownOption = true;
                continue;
            }

            if (EqualsToken(argument, "--all") ||
                EqualsToken(argument, "--modules") ||
                EqualsToken(argument, "--handles") ||
                EqualsToken(argument, "--pe") ||
                EqualsToken(argument, "--recurse") ||
                EqualsToken(argument, "--include-ntfs") ||
                EqualsToken(argument, "--include-prefetch"))
            {
                sawKnownOption = true;
                continue;
            }

            return false;
        }

        return sawKnownOption;
    }

    public static string GetAttemptedCommand(IReadOnlyList<string> args)
    {
        foreach (var argument in EnumerateCommandTokens(args))
        {
            if (EqualsToken(argument, "--help"))
            {
                return "help";
            }

            if (EqualsToken(argument, "--version") || EqualsToken(argument, "version"))
            {
                return "version";
            }

            if (EqualsToken(argument, "agent"))
            {
                return "agent";
            }

            if (EqualsToken(argument, "shell"))
            {
                return "shell";
            }
        }

        return "unknown";
    }

    public static bool IsShellEntry(IReadOnlyList<string> args) =>
        string.Equals(GetAttemptedCommand(args), "shell", StringComparison.Ordinal);

    public static CliParseResult Parse(IReadOnlyList<string> args) =>
        Parse(args, new Defaults(CliOutputMode.Text, null));

    internal static CliParseResult Parse(IReadOnlyList<string> args, Defaults defaults)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(defaults);
        if (args.Count == 0)
        {
            return Failure(defaults.OutputMode, "A command is required.");
        }

        var outputMode = ResolveOutputMode(args, defaults.OutputMode);
        var outputSeen = false;
        string? session = null;
        var sessionSeen = false;
        var noPromptSeen = false;
        var yesSeen = false;
        int? liveBufferMemoryMegabytes = null;
        var liveBufferSeen = false;
        int? timeoutSeconds = null;
        var timeoutSeen = false;
        string? filePath = null;
        var fileSeen = false;
        string? source = null;
        var sourceSeen = false;
        Guid? jobId = null;
        var jobIdSeen = false;
        var waitSeen = false;
        var allProcessesSeen = false;
        var processEntityIds = new List<string>();
        var processKeys = new List<string>();
        var modulesSeen = false;
        var handlesSeen = false;
        var peSeen = false;
        var peStringsSeen = false;
        var peStringExtractionMode = PeStringExtractionMode.Deferred;
        MemoryDumpKind? dumpKind = null;
        var dumpKindSeen = false;
        string? sourcePath = null;
        var sourcePathSeen = false;
        var recurseSeen = false;
        var includeNtfsSeen = false;
        var includePrefetchSeen = false;
        int? maxFiles = null;
        var maxFilesSeen = false;
        string? captureId = null;
        var captureIdSeen = false;
        string? pcapPath = null;
        var pcapPathSeen = false;
        string? zeekPath = null;
        var zeekPathSeen = false;
        string? wslDistributionName = null;
        var wslDistributionSeen = false;
        string? wslZeekCommand = null;
        var wslCommandSeen = false;
        string? procmonPath = null;
        var procmonPathSeen = false;
        var acceptEulaSeen = false;
        string? inputPath = null;
        var inputPathSeen = false;
        int? maxRows = null;
        var maxRowsSeen = false;
        int? phaseDurationSeconds = null;
        var phaseDurationSeen = false;
        int? maxPhaseCount = null;
        var maxPhaseCountSeen = false;
        int? initialProcessBatchSize = null;
        var initialProcessBatchSizeSeen = false;
        int? initialEventsPerProcess = null;
        var initialEventsPerProcessSeen = false;
        int? maxInFlightBatches = null;
        var maxInFlightBatchesSeen = false;
        int? maxPendingWriterWorkItems = null;
        var maxPendingWriterWorkItemsSeen = false;
        string? outputFileName = null;
        var outputFileNameSeen = false;
        int? acquisitionTimeoutSeconds = null;
        var acquisitionTimeoutSeen = false;
        string? imagePath = null;
        var imagePathSeen = false;
        string? displayName = null;
        var displayNameSeen = false;
        string? hostName = null;
        var hostNameSeen = false;
        string? osBuild = null;
        var osBuildSeen = false;
        string? acquisitionTool = null;
        var acquisitionToolSeen = false;
        string? acquisitionToolVersion = null;
        var acquisitionToolVersionSeen = false;
        string? acquisitionCommandLine = null;
        var acquisitionCommandLineSeen = false;
        string? privilegeState = null;
        var privilegeStateSeen = false;
        string? imageId = null;
        var imageIdSeen = false;
        var pluginNames = new List<string>();
        int? pluginTimeoutSeconds = null;
        var pluginTimeoutSeen = false;
        var positional = new List<string>();

        for (var index = 0; index < args.Count; index++)
        {
            var argument = args[index] ?? string.Empty;
            if (EqualsToken(argument, "--output"))
            {
                if (outputSeen)
                {
                    return Failure(outputMode, "--output may be supplied only once.");
                }

                outputSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--output requires text or json.");
                }

                if (!EqualsToken(args[index], "text") &&
                    !EqualsToken(args[index], "json"))
                {
                    return Failure(outputMode, "--output accepts only text or json.");
                }

                var requestedOutput = EqualsToken(args[index], "json")
                    ? CliOutputMode.Json
                    : CliOutputMode.Text;
                if (defaults.LockOutputMode && requestedOutput != defaults.OutputMode)
                {
                    return Failure(
                        defaults.OutputMode,
                        $"The shell output mode is fixed to {defaults.OutputMode.ToString().ToLowerInvariant()}.");
                }

                continue;
            }

            if (EqualsToken(argument, "--session"))
            {
                if (sessionSeen)
                {
                    return Failure(outputMode, "--session may be supplied only once.");
                }

                sessionSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--session requires an absolute session root or session.json path.");
                }

                session = args[index];
                continue;
            }

            if (EqualsToken(argument, "--no-prompt"))
            {
                if (noPromptSeen)
                {
                    return Failure(outputMode, "--no-prompt may be supplied only once.");
                }

                noPromptSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--yes"))
            {
                if (yesSeen)
                {
                    return Failure(outputMode, "--yes may be supplied only once.");
                }

                yesSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--wait"))
            {
                if (waitSeen)
                {
                    return Failure(outputMode, "--wait may be supplied only once.");
                }

                waitSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--accept-eula"))
            {
                if (acceptEulaSeen)
                {
                    return Failure(outputMode, "--accept-eula may be supplied only once.");
                }

                acceptEulaSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--all"))
            {
                if (allProcessesSeen)
                {
                    return Failure(outputMode, "--all may be supplied only once.");
                }

                allProcessesSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--modules"))
            {
                if (modulesSeen)
                {
                    return Failure(outputMode, "--modules may be supplied only once.");
                }

                modulesSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--handles"))
            {
                if (handlesSeen)
                {
                    return Failure(outputMode, "--handles may be supplied only once.");
                }

                handlesSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--pe"))
            {
                if (peSeen)
                {
                    return Failure(outputMode, "--pe may be supplied only once.");
                }

                peSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--recurse"))
            {
                if (recurseSeen)
                {
                    return Failure(outputMode, "--recurse may be supplied only once.");
                }

                recurseSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--include-ntfs"))
            {
                if (includeNtfsSeen)
                {
                    return Failure(outputMode, "--include-ntfs may be supplied only once.");
                }

                includeNtfsSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--include-prefetch"))
            {
                if (includePrefetchSeen)
                {
                    return Failure(outputMode, "--include-prefetch may be supplied only once.");
                }

                includePrefetchSeen = true;
                continue;
            }

            if (EqualsToken(argument, "--live-buffer-memory-mb"))
            {
                if (liveBufferSeen)
                {
                    return Failure(outputMode, "--live-buffer-memory-mb may be supplied only once.");
                }

                liveBufferSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.Integer,
                        CultureInfo.InvariantCulture,
                        out var requestedMemory) ||
                    requestedMemory is not (500 or 1024 or 2048))
                {
                    return Failure(outputMode, "--live-buffer-memory-mb accepts only 500, 1024, or 2048.");
                }

                liveBufferMemoryMegabytes = requestedMemory;
                continue;
            }

            if (EqualsToken(argument, "--timeout-seconds"))
            {
                if (timeoutSeen)
                {
                    return Failure(outputMode, "--timeout-seconds may be supplied only once.");
                }

                timeoutSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(
                        args[index],
                        NumberStyles.Integer,
                        CultureInfo.InvariantCulture,
                        out var requestedTimeout))
                {
                    return Failure(outputMode, "--timeout-seconds requires an integer value.");
                }

                timeoutSeconds = requestedTimeout;
                continue;
            }

            if (EqualsToken(argument, "--file"))
            {
                if (fileSeen)
                {
                    return Failure(outputMode, "--file may be supplied only once.");
                }

                fileSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--file requires an absolute JSON path.");
                }

                filePath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--source"))
            {
                if (sourceSeen)
                {
                    return Failure(outputMode, "--source may be supplied only once.");
                }

                sourceSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--source requires a supported capture source.");
                }

                source = args[index];
                continue;
            }

            if (EqualsToken(argument, "--job-id"))
            {
                if (jobIdSeen)
                {
                    return Failure(outputMode, "--job-id may be supplied only once.");
                }

                jobIdSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !Guid.TryParse(args[index], out var requestedJobId) ||
                    requestedJobId == Guid.Empty)
                {
                    return Failure(outputMode, "--job-id requires a non-empty GUID.");
                }

                jobId = requestedJobId;
                continue;
            }

            if (EqualsToken(argument, "--process-entity-id"))
            {
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--process-entity-id requires one durable process entity ID.");
                }

                if (processEntityIds.Count >= ViewerAgentEvidenceActionService.MaximumEnrichmentTargetCount)
                {
                    return Failure(
                        outputMode,
                        $"--process-entity-id accepts at most {ViewerAgentEvidenceActionService.MaximumEnrichmentTargetCount} targets.");
                }

                processEntityIds.Add(args[index]);
                continue;
            }

            if (EqualsToken(argument, "--process-key"))
            {
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--process-key requires one exact PID_StartTimeTicks value.");
                }

                if (processKeys.Count >= ViewerAgentEvidenceActionService.MaximumEnrichmentTargetCount)
                {
                    return Failure(
                        outputMode,
                        $"--process-key accepts at most {ViewerAgentEvidenceActionService.MaximumEnrichmentTargetCount} targets.");
                }

                processKeys.Add(args[index]);
                continue;
            }

            if (EqualsToken(argument, "--pe-strings"))
            {
                if (peStringsSeen)
                {
                    return Failure(outputMode, "--pe-strings may be supplied only once.");
                }

                peStringsSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !TryParsePeStringExtractionMode(args[index], out peStringExtractionMode))
                {
                    return Failure(outputMode, "--pe-strings accepts only deferred or immediate.");
                }

                continue;
            }

            if (EqualsToken(argument, "--kind"))
            {
                if (dumpKindSeen)
                {
                    return Failure(outputMode, "--kind may be supplied only once.");
                }

                dumpKindSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !TryParseMemoryDumpKind(args[index], out var requestedDumpKind))
                {
                    return Failure(outputMode, "--kind accepts only full or mini.");
                }

                dumpKind = requestedDumpKind;
                continue;
            }

            if (EqualsToken(argument, "--path"))
            {
                if (sourcePathSeen)
                {
                    return Failure(outputMode, "--path may be supplied only once.");
                }

                sourcePathSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--path requires an absolute file or folder path.");
                }

                sourcePath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--max-files"))
            {
                if (maxFilesSeen)
                {
                    return Failure(outputMode, "--max-files may be supplied only once.");
                }

                maxFilesSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var requestedMaxFiles))
                {
                    return Failure(outputMode, "--max-files requires an integer value.");
                }

                maxFiles = requestedMaxFiles;
                continue;
            }

            if (EqualsToken(argument, "--capture-id"))
            {
                if (captureIdSeen)
                {
                    return Failure(outputMode, "--capture-id may be supplied only once.");
                }

                captureIdSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--capture-id requires one bounded capture identifier.");
                }

                captureId = args[index];
                continue;
            }

            if (EqualsToken(argument, "--pcap-path"))
            {
                if (pcapPathSeen)
                {
                    return Failure(outputMode, "--pcap-path may be supplied only once.");
                }

                pcapPathSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--pcap-path requires one absolute PCAP or PCAPNG path.");
                }

                pcapPath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--zeek-path"))
            {
                if (zeekPathSeen)
                {
                    return Failure(outputMode, "--zeek-path may be supplied only once.");
                }

                zeekPathSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--zeek-path requires one absolute executable path.");
                }

                zeekPath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--wsl-distribution"))
            {
                if (wslDistributionSeen)
                {
                    return Failure(outputMode, "--wsl-distribution may be supplied only once.");
                }

                wslDistributionSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--wsl-distribution requires one bounded distribution name.");
                }

                wslDistributionName = args[index];
                continue;
            }

            if (EqualsToken(argument, "--wsl-command"))
            {
                if (wslCommandSeen)
                {
                    return Failure(outputMode, "--wsl-command may be supplied only once.");
                }

                wslCommandSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--wsl-command requires one bounded executable token.");
                }

                wslZeekCommand = args[index];
                continue;
            }

            if (EqualsToken(argument, "--procmon-path"))
            {
                if (procmonPathSeen)
                {
                    return Failure(outputMode, "--procmon-path may be supplied only once.");
                }

                procmonPathSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--procmon-path requires one absolute executable path.");
                }

                procmonPath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--input"))
            {
                if (inputPathSeen)
                {
                    return Failure(outputMode, "--input may be supplied only once.");
                }

                inputPathSeen = true;
                if (++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--input requires one absolute CSV or PML path.");
                }

                inputPath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--max-rows"))
            {
                if (maxRowsSeen)
                {
                    return Failure(outputMode, "--max-rows may be supplied only once.");
                }

                maxRowsSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var requestedMaxRows))
                {
                    return Failure(outputMode, "--max-rows requires an integer value.");
                }

                maxRows = requestedMaxRows;
                continue;
            }

            if (EqualsToken(argument, "--phase-duration-seconds"))
            {
                if (phaseDurationSeen)
                {
                    return Failure(outputMode, "--phase-duration-seconds may be supplied only once.");
                }

                phaseDurationSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--phase-duration-seconds requires an integer value.");
                }

                phaseDurationSeconds = value;
                continue;
            }

            if (EqualsToken(argument, "--max-phase-count"))
            {
                if (maxPhaseCountSeen)
                {
                    return Failure(outputMode, "--max-phase-count may be supplied only once.");
                }

                maxPhaseCountSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--max-phase-count requires an integer value.");
                }

                maxPhaseCount = value;
                continue;
            }

            if (EqualsToken(argument, "--initial-process-batch-size"))
            {
                if (initialProcessBatchSizeSeen)
                {
                    return Failure(outputMode, "--initial-process-batch-size may be supplied only once.");
                }

                initialProcessBatchSizeSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--initial-process-batch-size requires an integer value.");
                }

                initialProcessBatchSize = value;
                continue;
            }

            if (EqualsToken(argument, "--initial-events-per-process"))
            {
                if (initialEventsPerProcessSeen)
                {
                    return Failure(outputMode, "--initial-events-per-process may be supplied only once.");
                }

                initialEventsPerProcessSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--initial-events-per-process requires an integer value.");
                }

                initialEventsPerProcess = value;
                continue;
            }

            if (EqualsToken(argument, "--max-in-flight-batches"))
            {
                if (maxInFlightBatchesSeen)
                {
                    return Failure(outputMode, "--max-in-flight-batches may be supplied only once.");
                }

                maxInFlightBatchesSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--max-in-flight-batches requires an integer value.");
                }

                maxInFlightBatches = value;
                continue;
            }

            if (EqualsToken(argument, "--max-pending-writer-work-items"))
            {
                if (maxPendingWriterWorkItemsSeen)
                {
                    return Failure(outputMode, "--max-pending-writer-work-items may be supplied only once.");
                }

                maxPendingWriterWorkItemsSeen = true;
                if (++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--max-pending-writer-work-items requires an integer value.");
                }

                maxPendingWriterWorkItems = value;
                continue;
            }

            if (EqualsToken(argument, "--output-file-name"))
            {
                if (outputFileNameSeen || ++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--output-file-name requires one leaf file name and may be supplied only once.");
                }

                outputFileNameSeen = true;
                outputFileName = args[index];
                continue;
            }

            if (EqualsToken(argument, "--acquisition-timeout-seconds"))
            {
                if (acquisitionTimeoutSeen || ++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--acquisition-timeout-seconds requires one integer value and may be supplied only once.");
                }

                acquisitionTimeoutSeen = true;
                acquisitionTimeoutSeconds = value;
                continue;
            }

            if (EqualsToken(argument, "--image-path"))
            {
                if (imagePathSeen || ++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--image-path requires one absolute memory-image path and may be supplied only once.");
                }

                imagePathSeen = true;
                imagePath = args[index];
                continue;
            }

            if (EqualsToken(argument, "--image-id"))
            {
                if (imageIdSeen || ++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, "--image-id requires one staged image identifier and may be supplied only once.");
                }

                imageIdSeen = true;
                imageId = args[index];
                continue;
            }

            if (EqualsToken(argument, "--plugin"))
            {
                if (++index >= args.Count || IsOption(args[index]) ||
                    pluginNames.Count >= AgentMemoryActionPolicy.MaximumPluginCount)
                {
                    return Failure(outputMode, $"--plugin requires a name and accepts at most {AgentMemoryActionPolicy.MaximumPluginCount} values.");
                }

                pluginNames.Add(args[index]);
                continue;
            }

            if (EqualsToken(argument, "--plugin-timeout-seconds"))
            {
                if (pluginTimeoutSeen || ++index >= args.Count || IsOption(args[index]) ||
                    !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    return Failure(outputMode, "--plugin-timeout-seconds requires one integer value and may be supplied only once.");
                }

                pluginTimeoutSeen = true;
                pluginTimeoutSeconds = value;
                continue;
            }

            if (EqualsToken(argument, "--display-name") ||
                EqualsToken(argument, "--host-name") ||
                EqualsToken(argument, "--os-build") ||
                EqualsToken(argument, "--acquisition-tool") ||
                EqualsToken(argument, "--acquisition-tool-version") ||
                EqualsToken(argument, "--acquisition-command-line") ||
                EqualsToken(argument, "--privilege-state"))
            {
                var option = argument.ToLowerInvariant();
                var duplicate = option switch
                {
                    "--display-name" => displayNameSeen,
                    "--host-name" => hostNameSeen,
                    "--os-build" => osBuildSeen,
                    "--acquisition-tool" => acquisitionToolSeen,
                    "--acquisition-tool-version" => acquisitionToolVersionSeen,
                    "--acquisition-command-line" => acquisitionCommandLineSeen,
                    _ => privilegeStateSeen
                };
                if (duplicate || ++index >= args.Count || IsOption(args[index]))
                {
                    return Failure(outputMode, $"{option} requires one value and may be supplied only once.");
                }

                switch (option)
                {
                    case "--display-name": displayNameSeen = true; displayName = args[index]; break;
                    case "--host-name": hostNameSeen = true; hostName = args[index]; break;
                    case "--os-build": osBuildSeen = true; osBuild = args[index]; break;
                    case "--acquisition-tool": acquisitionToolSeen = true; acquisitionTool = args[index]; break;
                    case "--acquisition-tool-version": acquisitionToolVersionSeen = true; acquisitionToolVersion = args[index]; break;
                    case "--acquisition-command-line": acquisitionCommandLineSeen = true; acquisitionCommandLine = args[index]; break;
                    default: privilegeStateSeen = true; privilegeState = args[index]; break;
                }

                continue;
            }

            if (IsOption(argument) &&
                !EqualsToken(argument, "--help") &&
                !EqualsToken(argument, "--version"))
            {
                return Failure(outputMode, $"Unknown option '{CliValueSanitizer.Value(argument)}'.");
            }

            positional.Add(argument);
        }

        var kind = Match(positional);
        if (kind == CliCommandKind.Unknown)
        {
            return Failure(outputMode, "The command is unknown or malformed.");
        }

        var definition = CliCommandRegistry.Get(kind);
        var effectiveSession = sessionSeen
            ? session
            : definition.RequiresSession
                ? defaults.SessionTarget
                : null;
        if (definition.RequiresSession && string.IsNullOrWhiteSpace(effectiveSession))
        {
            return Failure(outputMode, $"{definition.Name} requires --session.");
        }

        if (!definition.RequiresSession && sessionSeen && kind != CliCommandKind.Shell)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --session.");
        }

        if (noPromptSeen && kind != CliCommandKind.Shell)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --no-prompt.");
        }

        if (yesSeen && kind is not
            (CliCommandKind.AgentStop or
             CliCommandKind.AgentPairingRotate or
             CliCommandKind.AgentPairingRevoke or
             CliCommandKind.AgentProcessDump or
             CliCommandKind.AgentMemoryAcquire or
             CliCommandKind.HostMonitoringDeploy or
             CliCommandKind.HostMonitoringReverse))
        {
            return Failure(outputMode, $"{definition.Name} does not accept --yes.");
        }

        if (!yesSeen && kind is
            (CliCommandKind.AgentStop or
             CliCommandKind.AgentPairingRotate or
             CliCommandKind.AgentPairingRevoke or
             CliCommandKind.AgentProcessDump or
             CliCommandKind.AgentMemoryAcquire or
             CliCommandKind.HostMonitoringDeploy or
             CliCommandKind.HostMonitoringReverse))
        {
            return Failure(outputMode, $"{definition.Name} requires --yes.");
        }

        if (liveBufferSeen && kind != CliCommandKind.AgentStart)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --live-buffer-memory-mb.");
        }

        if (timeoutSeen && kind is not
            (CliCommandKind.AgentStop or
             CliCommandKind.CaptureStart or
             CliCommandKind.CaptureStop or
             CliCommandKind.AgentJobWait or
             CliCommandKind.AgentEvidenceEnrich or
             CliCommandKind.AgentProcessDump or
             CliCommandKind.AgentFilesystemImport or
             CliCommandKind.AgentNetworkStart or
             CliCommandKind.AgentNetworkStop or
             CliCommandKind.AgentZeekRun or
             CliCommandKind.AgentSqliteBenchmarkStart or
             CliCommandKind.AgentMemoryAcquire or
             CliCommandKind.AgentMemoryImport or
             CliCommandKind.AgentVolatilityRun))
        {
            return Failure(outputMode, $"{definition.Name} does not accept --timeout-seconds.");
        }

        if (kind == CliCommandKind.AgentStop && timeoutSeen &&
            timeoutSeconds is (< 1 or > 120))
        {
            return Failure(outputMode, "agent stop --timeout-seconds requires an integer from 1 through 120.");
        }

        if (timeoutSeen && kind is not CliCommandKind.AgentStop &&
            timeoutSeconds is (< 1 or > ViewerAgentCaptureActionService.MaximumWaitTimeoutSeconds))
        {
            return Failure(
                outputMode,
                $"--timeout-seconds requires an integer from 1 through {ViewerAgentCaptureActionService.MaximumWaitTimeoutSeconds}.");
        }

        if (fileSeen && kind is not
            (CliCommandKind.CaptureConfigurationCheck or
             CliCommandKind.CaptureConfigurationSave or
             CliCommandKind.HostMonitoringConfigurationCheck or
             CliCommandKind.HostMonitoringConfigurationSave))
        {
            return Failure(outputMode, $"{definition.Name} does not accept --file.");
        }

        if (kind is
                (CliCommandKind.CaptureConfigurationSave or
                 CliCommandKind.HostMonitoringConfigurationSave) &&
            !fileSeen)
        {
            return Failure(outputMode, $"{definition.Name} requires --file.");
        }

        if (fileSeen && !Path.IsPathFullyQualified(filePath!))
        {
            return Failure(outputMode, "--file requires an absolute JSON path.");
        }

        if (sourceSeen && kind is not
            (CliCommandKind.CaptureSourceStart or CliCommandKind.CaptureSourceStop))
        {
            return Failure(outputMode, $"{definition.Name} does not accept --source.");
        }

        if (kind is (CliCommandKind.CaptureSourceStart or CliCommandKind.CaptureSourceStop) && !sourceSeen)
        {
            return Failure(outputMode, $"{definition.Name} requires --source.");
        }

        if (sourceSeen && !new[]
            {
                "Runtime", "ETW", "Security", "PowerShell", "WindowsOther", "Sysmon"
            }.Contains(source, StringComparer.OrdinalIgnoreCase))
        {
            return Failure(
                outputMode,
                "--source accepts only Runtime, ETW, Security, PowerShell, WindowsOther, or Sysmon.");
        }

        if (jobIdSeen && kind is not
            (CliCommandKind.AgentJobStatus or
             CliCommandKind.AgentJobWait or
             CliCommandKind.AgentJobCancel))
        {
            return Failure(outputMode, $"{definition.Name} does not accept --job-id.");
        }

        if (kind is
            (CliCommandKind.AgentJobStatus or
             CliCommandKind.AgentJobWait or
             CliCommandKind.AgentJobCancel) && !jobIdSeen)
        {
            return Failure(outputMode, $"{definition.Name} requires --job-id.");
        }

        if (waitSeen && kind is not
            (CliCommandKind.CaptureStart or
             CliCommandKind.CaptureStop or
             CliCommandKind.AgentEvidenceEnrich or
             CliCommandKind.AgentProcessDump or
             CliCommandKind.AgentFilesystemImport or
             CliCommandKind.AgentNetworkStart or
             CliCommandKind.AgentNetworkStop or
             CliCommandKind.AgentZeekRun or
             CliCommandKind.AgentProcessMonitorStart or
             CliCommandKind.AgentProcessMonitorStop or
             CliCommandKind.AgentProcessMonitorImport or
             CliCommandKind.AgentSqliteBenchmarkStart or
             CliCommandKind.AgentMemoryAcquire or
             CliCommandKind.AgentMemoryImport or
             CliCommandKind.AgentVolatilityRun))
        {
            return Failure(outputMode, $"{definition.Name} does not accept --wait.");
        }

        if (timeoutSeen && kind is
                (CliCommandKind.CaptureStart or
                 CliCommandKind.CaptureStop or
                 CliCommandKind.AgentEvidenceEnrich or
                 CliCommandKind.AgentProcessDump or
                 CliCommandKind.AgentFilesystemImport or
                 CliCommandKind.AgentNetworkStart or
                 CliCommandKind.AgentNetworkStop or
                 CliCommandKind.AgentZeekRun or
                 CliCommandKind.AgentSqliteBenchmarkStart or
                 CliCommandKind.AgentMemoryAcquire or
                 CliCommandKind.AgentMemoryImport or
                 CliCommandKind.AgentVolatilityRun) &&
            !waitSeen)
        {
            return Failure(outputMode, $"{definition.Name} accepts --timeout-seconds only with --wait.");
        }

        var isEnrichment = kind == CliCommandKind.AgentEvidenceEnrich;
        if ((allProcessesSeen || processEntityIds.Count > 0 || modulesSeen || handlesSeen || peSeen || peStringsSeen) &&
            !isEnrichment)
        {
            return Failure(outputMode, $"{definition.Name} does not accept enrichment scope or workload options.");
        }

        if (isEnrichment)
        {
            var scopeKinds = (allProcessesSeen ? 1 : 0) +
                             (processEntityIds.Count > 0 ? 1 : 0) +
                             (processKeys.Count > 0 ? 1 : 0);
            if (scopeKinds != 1)
            {
                return Failure(
                    outputMode,
                    "agent evidence enrich requires exactly one scope: --all, --process-entity-id, or --process-key.");
            }

            if (!modulesSeen && !handlesSeen && !peSeen)
            {
                return Failure(outputMode, "agent evidence enrich requires --modules, --handles, or --pe.");
            }

            if (peStringsSeen && !peSeen)
            {
                return Failure(outputMode, "--pe-strings requires --pe.");
            }

            if (processEntityIds.Count > 0)
            {
                if (!ViewerAgentEvidenceActionService.TryNormalizeProcessEntityIds(
                        processEntityIds,
                        out var normalizedEntityIds,
                        out var entityError))
                {
                    return Failure(outputMode, entityError);
                }

                processEntityIds = normalizedEntityIds.ToList();
            }

            if (processKeys.Count > 0)
            {
                if (!ViewerAgentEvidenceActionService.TryNormalizeProcessKeys(
                        processKeys,
                        out var normalizedProcessKeys,
                        out var processKeyError))
                {
                    return Failure(outputMode, processKeyError);
                }

                processKeys = normalizedProcessKeys.ToList();
            }
        }

        var isProcessDump = kind == CliCommandKind.AgentProcessDump;
        if (dumpKindSeen && !isProcessDump)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --kind.");
        }

        if (processKeys.Count > 0 && !isEnrichment && !isProcessDump)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --process-key.");
        }

        if (isProcessDump)
        {
            if (processKeys.Count != 1)
            {
                return Failure(outputMode, "agent process dump requires exactly one --process-key.");
            }

            if (!dumpKind.HasValue)
            {
                return Failure(outputMode, "agent process dump requires --kind full or mini.");
            }

            if (!ViewerAgentEvidenceActionService.TryNormalizeExactProcessKey(processKeys[0], out var normalizedProcessKey))
            {
                return Failure(outputMode, "--process-key requires exact PID_StartTimeTicks form; PID-only targets are not accepted.");
            }

            processKeys = [normalizedProcessKey];
        }

        var isFilesystemImport = kind == CliCommandKind.AgentFilesystemImport;
        if ((sourcePathSeen || recurseSeen || includeNtfsSeen || includePrefetchSeen || maxFilesSeen) && !isFilesystemImport)
        {
            return Failure(outputMode, $"{definition.Name} does not accept filesystem import options.");
        }

        if (isFilesystemImport)
        {
            if (string.IsNullOrWhiteSpace(sourcePath))
            {
                return Failure(outputMode, "agent filesystem import requires --path.");
            }

            if (!Path.IsPathFullyQualified(sourcePath))
            {
                return Failure(outputMode, "--path requires an absolute file or folder path.");
            }

            if (maxFiles is < 1 or > ViewerAgentEvidenceActionService.MaximumFilesystemImportFiles)
            {
                return Failure(
                    outputMode,
                    $"--max-files requires an integer from 1 through {ViewerAgentEvidenceActionService.MaximumFilesystemImportFiles}.");
            }
        }

        var isZeek = kind == CliCommandKind.AgentZeekRun;
        if ((captureIdSeen || pcapPathSeen || zeekPathSeen || wslDistributionSeen || wslCommandSeen) && !isZeek)
        {
            return Failure(outputMode, $"{definition.Name} does not accept Zeek source or tool-mode options.");
        }

        if (isZeek)
        {
            if (captureIdSeen == pcapPathSeen)
            {
                return Failure(outputMode, "agent zeek run requires exactly one --capture-id or --pcap-path.");
            }

            if (captureIdSeen && !AgentToolActionPolicy.TryNormalizeCaptureId(captureId, out captureId))
            {
                return Failure(outputMode, "--capture-id is malformed or exceeds the bounded identifier length.");
            }

            if (pcapPathSeen &&
                (!AgentToolActionPolicy.TryNormalizeAbsolutePath(pcapPath, out pcapPath) ||
                 !AgentToolActionPolicy.IsSupportedPcapPath(pcapPath)))
            {
                return Failure(outputMode, "--pcap-path requires an absolute PCAP or PCAPNG path.");
            }

            if (!AgentToolActionPolicy.TryNormalizeZeekToolMode(
                    zeekPath,
                    wslDistributionName,
                    wslZeekCommand,
                    out _,
                    out zeekPath,
                    out wslDistributionName,
                    out wslZeekCommand,
                    out var modeError))
            {
                return Failure(outputMode, modeError);
            }
        }

        var isProcessMonitorStart = kind == CliCommandKind.AgentProcessMonitorStart;
        var isProcessMonitorStop = kind == CliCommandKind.AgentProcessMonitorStop;
        var isProcessMonitorImport = kind == CliCommandKind.AgentProcessMonitorImport;
        var isProcessMonitor = isProcessMonitorStart || isProcessMonitorStop || isProcessMonitorImport;
        if (procmonPathSeen && !isProcessMonitor)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --procmon-path.");
        }

        if (procmonPathSeen &&
            !AgentToolActionPolicy.TryNormalizeOptionalProcessMonitorPath(procmonPath, out procmonPath))
        {
            return Failure(outputMode, "--procmon-path requires an absolute Procmon.exe or Procmon64.exe path.");
        }

        if (acceptEulaSeen && !isProcessMonitorStart)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --accept-eula.");
        }

        if (isProcessMonitorStart && !acceptEulaSeen)
        {
            return Failure(outputMode, "agent procmon start requires --accept-eula.");
        }

        if (inputPathSeen && !isProcessMonitorImport)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --input.");
        }

        if (isProcessMonitorImport && !inputPathSeen)
        {
            return Failure(outputMode, "agent procmon import requires --input.");
        }

        if (inputPathSeen &&
            (!AgentToolActionPolicy.TryNormalizeAbsolutePath(inputPath, out inputPath) ||
             !AgentToolActionPolicy.IsSupportedProcessMonitorInputPath(inputPath)))
        {
            return Failure(outputMode, "--input requires an absolute CSV or PML path.");
        }

        if (maxRowsSeen && !isProcessMonitorStart && !isProcessMonitorImport)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --max-rows.");
        }

        if (maxRows is < 1 or > AgentToolActionPolicy.MaximumProcessMonitorRows)
        {
            return Failure(
                outputMode,
                $"--max-rows requires an integer from 1 through {AgentToolActionPolicy.MaximumProcessMonitorRows}.");
        }

        var hasBenchmarkOptions = phaseDurationSeen ||
                                  maxPhaseCountSeen ||
                                  initialProcessBatchSizeSeen ||
                                  initialEventsPerProcessSeen ||
                                  maxInFlightBatchesSeen ||
                                  maxPendingWriterWorkItemsSeen;
        if (hasBenchmarkOptions && kind != CliCommandKind.AgentSqliteBenchmarkStart)
        {
            return Failure(outputMode, $"{definition.Name} does not accept SQLite benchmark options.");
        }

        if (kind == CliCommandKind.AgentSqliteBenchmarkStart)
        {
            var benchmarkDefaults = new QueueSqliteBenchmarkCommand();
            var benchmark = benchmarkDefaults with
            {
                PhaseDurationSeconds = phaseDurationSeconds ?? benchmarkDefaults.PhaseDurationSeconds,
                MaxPhaseCount = maxPhaseCount ?? benchmarkDefaults.MaxPhaseCount,
                InitialProcessBatchSize = initialProcessBatchSize ?? benchmarkDefaults.InitialProcessBatchSize,
                InitialEventsPerProcess = initialEventsPerProcess ?? benchmarkDefaults.InitialEventsPerProcess,
                MaxInFlightBatches = maxInFlightBatches ?? benchmarkDefaults.MaxInFlightBatches,
                MaxPendingWriterWorkItems = maxPendingWriterWorkItems ?? benchmarkDefaults.MaxPendingWriterWorkItems
            };
            if (!AgentToolActionPolicy.TryValidateBenchmark(benchmark, out var benchmarkError))
            {
                return Failure(outputMode, benchmarkError);
            }
        }

        var isMemoryAcquire = kind == CliCommandKind.AgentMemoryAcquire;
        var isMemoryImport = kind == CliCommandKind.AgentMemoryImport;
        var isVolatility = kind == CliCommandKind.AgentVolatilityRun;
        var hasMemoryAcquireOptions = outputFileNameSeen || acquisitionTimeoutSeen;
        var hasMemoryImportMetadata = displayNameSeen || hostNameSeen || osBuildSeen || acquisitionToolSeen ||
                                      acquisitionToolVersionSeen || acquisitionCommandLineSeen || privilegeStateSeen;
        var hasVolatilityOptions = imageIdSeen || pluginNames.Count > 0 || pluginTimeoutSeen;
        if (hasMemoryAcquireOptions && !isMemoryAcquire)
        {
            return Failure(outputMode, $"{definition.Name} does not accept memory-acquisition options.");
        }

        if (hasMemoryImportMetadata && !isMemoryImport)
        {
            return Failure(outputMode, $"{definition.Name} does not accept memory-import metadata.");
        }

        if (imagePathSeen && !isMemoryImport && !isVolatility)
        {
            return Failure(outputMode, $"{definition.Name} does not accept --image-path.");
        }

        if (hasVolatilityOptions && !isVolatility)
        {
            return Failure(outputMode, $"{definition.Name} does not accept Volatility options.");
        }

        if (isMemoryAcquire)
        {
            if (!AgentMemoryActionPolicy.TryNormalizeOptionalOutputFileName(outputFileName, out outputFileName))
            {
                return Failure(outputMode, "--output-file-name must be a supported bounded leaf file name without a directory.");
            }

            acquisitionTimeoutSeconds ??= AgentMemoryActionPolicy.DefaultAcquisitionTimeoutSeconds;
            if (!AgentMemoryActionPolicy.IsValidAcquisitionTimeout(acquisitionTimeoutSeconds.Value))
            {
                return Failure(outputMode, $"--acquisition-timeout-seconds requires an integer from {AgentMemoryActionPolicy.MinimumAcquisitionTimeoutSeconds} through {AgentMemoryActionPolicy.MaximumAcquisitionTimeoutSeconds}.");
            }
        }

        if ((isMemoryImport || isVolatility) && imagePathSeen)
        {
            if (!AgentToolActionPolicy.TryNormalizeAbsolutePath(imagePath, out imagePath) ||
                !AgentMemoryActionPolicy.IsSupportedImagePath(imagePath))
            {
                return Failure(outputMode, "--image-path requires an absolute path with a supported memory-image extension.");
            }
        }

        if (isMemoryImport)
        {
            if (!imagePathSeen)
            {
                return Failure(outputMode, "agent memory import requires --image-path.");
            }

            var metadata = new[]
            {
                ("--display-name", displayName, AgentMemoryActionPolicy.MaximumMetadataLength),
                ("--host-name", hostName, AgentMemoryActionPolicy.MaximumMetadataLength),
                ("--os-build", osBuild, AgentMemoryActionPolicy.MaximumMetadataLength),
                ("--acquisition-tool", acquisitionTool, AgentMemoryActionPolicy.MaximumMetadataLength),
                ("--acquisition-tool-version", acquisitionToolVersion, AgentMemoryActionPolicy.MaximumMetadataLength),
                ("--acquisition-command-line", acquisitionCommandLine, AgentMemoryActionPolicy.MaximumCommandLineMetadataLength),
                ("--privilege-state", privilegeState, AgentMemoryActionPolicy.MaximumMetadataLength)
            };
            foreach (var field in metadata)
            {
                if (!AgentMemoryActionPolicy.TryNormalizeOptionalMetadata(field.Item2, field.Item3, out _))
                {
                    return Failure(outputMode, $"{field.Item1} is too long or contains control characters.");
                }
            }
        }

        if (isVolatility)
        {
            if (imageIdSeen == imagePathSeen)
            {
                return Failure(outputMode, "agent volatility run requires exactly one --image-id or --image-path.");
            }

            if (imageIdSeen && !AgentMemoryActionPolicy.TryNormalizeImageId(imageId, out imageId))
            {
                return Failure(outputMode, "--image-id is malformed or exceeds the bounded identifier length.");
            }

            if (!AgentMemoryActionPolicy.TryNormalizePlugins(pluginNames, out var normalizedPlugins, out var pluginError))
            {
                return Failure(outputMode, pluginError);
            }

            pluginNames = normalizedPlugins.ToList();
            pluginTimeoutSeconds ??= AgentMemoryActionPolicy.DefaultPluginTimeoutSeconds;
            if (!AgentMemoryActionPolicy.IsValidPluginTimeout(pluginTimeoutSeconds.Value))
            {
                return Failure(outputMode, $"--plugin-timeout-seconds requires an integer from {AgentMemoryActionPolicy.MinimumPluginTimeoutSeconds} through {AgentMemoryActionPolicy.MaximumPluginTimeoutSeconds}.");
            }
        }

        return new CliParseResult(
            new CliInvocation(
                kind,
                definition.Name,
                outputMode,
                effectiveSession,
                noPromptSeen,
                yesSeen,
                liveBufferMemoryMegabytes,
                timeoutSeconds,
                filePath,
                source,
                jobId,
                waitSeen,
                allProcessesSeen,
                processEntityIds.ToArray(),
                processKeys.ToArray(),
                modulesSeen,
                handlesSeen,
                peSeen,
                peStringExtractionMode,
                dumpKind,
                sourcePath,
                recurseSeen,
                (isFilesystemImport && !includeNtfsSeen && !includePrefetchSeen) || includeNtfsSeen,
                (isFilesystemImport && !includeNtfsSeen && !includePrefetchSeen) || includePrefetchSeen,
                isFilesystemImport ? maxFiles ?? ViewerAgentEvidenceActionService.MaximumFilesystemImportFiles : null,
                captureId,
                pcapPath,
                zeekPath,
                wslDistributionName,
                wslZeekCommand,
                procmonPath,
                acceptEulaSeen,
                inputPath,
                isProcessMonitorStart || isProcessMonitorImport
                    ? maxRows ?? AgentToolActionPolicy.MaximumProcessMonitorRows
                    : null,
                phaseDurationSeconds,
                maxPhaseCount,
                initialProcessBatchSize,
                initialEventsPerProcess,
                maxInFlightBatches,
                maxPendingWriterWorkItems,
                outputFileName,
                acquisitionTimeoutSeconds,
                imagePath,
                displayName,
                hostName,
                osBuild,
                acquisitionTool,
                acquisitionToolVersion,
                acquisitionCommandLine,
                privilegeState,
                imageId,
                pluginNames.ToArray(),
                pluginTimeoutSeconds),
            outputMode,
            string.Empty,
            string.Empty);
    }

    private static CliCommandKind Match(IReadOnlyList<string> positional)
    {
        if (Matches(positional, "--help"))
        {
            return CliCommandKind.Help;
        }

        if (Matches(positional, "--version") || Matches(positional, "version"))
        {
            return CliCommandKind.Version;
        }

        if (Matches(positional, "agent", "discover"))
        {
            return CliCommandKind.AgentDiscover;
        }

        if (Matches(positional, "agent", "status"))
        {
            return CliCommandKind.AgentStatus;
        }

        if (Matches(positional, "agent", "capabilities"))
        {
            return CliCommandKind.AgentCapabilities;
        }

        if (Matches(positional, "agent", "capture", "configuration", "show"))
        {
            return CliCommandKind.CaptureConfigurationShow;
        }

        if (Matches(positional, "agent", "capture", "configuration", "check"))
        {
            return CliCommandKind.CaptureConfigurationCheck;
        }

        if (Matches(positional, "agent", "capture", "configuration", "save"))
        {
            return CliCommandKind.CaptureConfigurationSave;
        }

        if (Matches(positional, "agent", "capture", "start"))
        {
            return CliCommandKind.CaptureStart;
        }

        if (Matches(positional, "agent", "capture", "stop"))
        {
            return CliCommandKind.CaptureStop;
        }

        if (Matches(positional, "agent", "capture", "source", "start"))
        {
            return CliCommandKind.CaptureSourceStart;
        }

        if (Matches(positional, "agent", "capture", "source", "stop"))
        {
            return CliCommandKind.CaptureSourceStop;
        }

        if (Matches(positional, "agent", "job", "list"))
        {
            return CliCommandKind.AgentJobList;
        }

        if (Matches(positional, "agent", "job", "status"))
        {
            return CliCommandKind.AgentJobStatus;
        }

        if (Matches(positional, "agent", "job", "wait"))
        {
            return CliCommandKind.AgentJobWait;
        }

        if (Matches(positional, "agent", "job", "cancel"))
        {
            return CliCommandKind.AgentJobCancel;
        }

        if (Matches(positional, "agent", "evidence", "enrich"))
        {
            return CliCommandKind.AgentEvidenceEnrich;
        }

        if (Matches(positional, "agent", "process", "dump"))
        {
            return CliCommandKind.AgentProcessDump;
        }

        if (Matches(positional, "agent", "filesystem", "import"))
        {
            return CliCommandKind.AgentFilesystemImport;
        }

        if (Matches(positional, "agent", "network", "start"))
        {
            return CliCommandKind.AgentNetworkStart;
        }

        if (Matches(positional, "agent", "network", "stop"))
        {
            return CliCommandKind.AgentNetworkStop;
        }

        if (Matches(positional, "agent", "zeek", "run"))
        {
            return CliCommandKind.AgentZeekRun;
        }

        if (Matches(positional, "agent", "procmon", "start"))
        {
            return CliCommandKind.AgentProcessMonitorStart;
        }

        if (Matches(positional, "agent", "procmon", "stop"))
        {
            return CliCommandKind.AgentProcessMonitorStop;
        }

        if (Matches(positional, "agent", "procmon", "import"))
        {
            return CliCommandKind.AgentProcessMonitorImport;
        }

        if (Matches(positional, "agent", "sqlite", "benchmark", "start"))
        {
            return CliCommandKind.AgentSqliteBenchmarkStart;
        }

        if (Matches(positional, "agent", "memory", "acquire"))
        {
            return CliCommandKind.AgentMemoryAcquire;
        }

        if (Matches(positional, "agent", "memory", "import"))
        {
            return CliCommandKind.AgentMemoryImport;
        }

        if (Matches(positional, "agent", "volatility", "run"))
        {
            return CliCommandKind.AgentVolatilityRun;
        }

        if (Matches(positional, "agent", "monitoring", "configuration", "show"))
        {
            return CliCommandKind.HostMonitoringConfigurationShow;
        }

        if (Matches(positional, "agent", "monitoring", "configuration", "check"))
        {
            return CliCommandKind.HostMonitoringConfigurationCheck;
        }

        if (Matches(positional, "agent", "monitoring", "configuration", "save"))
        {
            return CliCommandKind.HostMonitoringConfigurationSave;
        }

        if (Matches(positional, "agent", "monitoring", "deploy"))
        {
            return CliCommandKind.HostMonitoringDeploy;
        }

        if (Matches(positional, "agent", "monitoring", "reverse"))
        {
            return CliCommandKind.HostMonitoringReverse;
        }

        if (Matches(positional, "agent", "reconnect"))
        {
            return CliCommandKind.AgentReconnect;
        }

        if (Matches(positional, "agent", "start"))
        {
            return CliCommandKind.AgentStart;
        }

        if (Matches(positional, "agent", "stop"))
        {
            return CliCommandKind.AgentStop;
        }

        if (Matches(positional, "agent", "pairing", "status"))
        {
            return CliCommandKind.AgentPairingStatus;
        }

        if (Matches(positional, "agent", "pairing", "rotate"))
        {
            return CliCommandKind.AgentPairingRotate;
        }

        if (Matches(positional, "agent", "pairing", "revoke"))
        {
            return CliCommandKind.AgentPairingRevoke;
        }

        if (Matches(positional, "shell"))
        {
            return CliCommandKind.Shell;
        }

        return CliCommandKind.Unknown;
    }

    private static bool TryParsePeStringExtractionMode(
        string value,
        out PeStringExtractionMode mode)
    {
        if (string.Equals(value, "deferred", StringComparison.OrdinalIgnoreCase))
        {
            mode = PeStringExtractionMode.Deferred;
            return true;
        }

        if (string.Equals(value, "immediate", StringComparison.OrdinalIgnoreCase))
        {
            mode = PeStringExtractionMode.Immediate;
            return true;
        }

        mode = default;
        return false;
    }

    private static bool TryParseMemoryDumpKind(string value, out MemoryDumpKind kind)
    {
        if (string.Equals(value, "full", StringComparison.OrdinalIgnoreCase))
        {
            kind = MemoryDumpKind.Full;
            return true;
        }

        if (string.Equals(value, "mini", StringComparison.OrdinalIgnoreCase))
        {
            kind = MemoryDumpKind.Mini;
            return true;
        }

        kind = default;
        return false;
    }

    private static bool Matches(IReadOnlyList<string> actual, params string[] expected) =>
        actual.Count == expected.Length &&
        actual.Zip(expected).All(pair => EqualsToken(pair.First, pair.Second));

    private static bool EqualsToken(string? left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool IsKnownCommandToken(string? value) =>
        EqualsToken(value, "--help") ||
        EqualsToken(value, "--version") ||
        EqualsToken(value, "version") ||
        EqualsToken(value, "agent") ||
        EqualsToken(value, "shell");

    private static IEnumerable<string?> EnumerateCommandTokens(IReadOnlyList<string> args)
    {
        for (var index = 0; index < args.Count; index++)
        {
            var argument = args[index];
            if (EqualsToken(argument, "--output") ||
                EqualsToken(argument, "--session") ||
                EqualsToken(argument, "--live-buffer-memory-mb") ||
                EqualsToken(argument, "--timeout-seconds") ||
                EqualsToken(argument, "--file") ||
                EqualsToken(argument, "--source") ||
                EqualsToken(argument, "--job-id") ||
                EqualsToken(argument, "--process-entity-id") ||
                EqualsToken(argument, "--process-key") ||
                EqualsToken(argument, "--pe-strings") ||
                EqualsToken(argument, "--kind") ||
                EqualsToken(argument, "--path") ||
                EqualsToken(argument, "--max-files") ||
                EqualsToken(argument, "--capture-id") ||
                EqualsToken(argument, "--pcap-path") ||
                EqualsToken(argument, "--zeek-path") ||
                EqualsToken(argument, "--wsl-distribution") ||
                EqualsToken(argument, "--wsl-command") ||
                EqualsToken(argument, "--procmon-path") ||
                EqualsToken(argument, "--input") ||
                EqualsToken(argument, "--max-rows") ||
                EqualsToken(argument, "--phase-duration-seconds") ||
                EqualsToken(argument, "--max-phase-count") ||
                EqualsToken(argument, "--initial-process-batch-size") ||
                EqualsToken(argument, "--initial-events-per-process") ||
                EqualsToken(argument, "--max-in-flight-batches") ||
                EqualsToken(argument, "--max-pending-writer-work-items") ||
                EqualsToken(argument, "--output-file-name") ||
                EqualsToken(argument, "--acquisition-timeout-seconds") ||
                EqualsToken(argument, "--image-path") ||
                EqualsToken(argument, "--display-name") ||
                EqualsToken(argument, "--host-name") ||
                EqualsToken(argument, "--os-build") ||
                EqualsToken(argument, "--acquisition-tool") ||
                EqualsToken(argument, "--acquisition-tool-version") ||
                EqualsToken(argument, "--acquisition-command-line") ||
                EqualsToken(argument, "--privilege-state") ||
                EqualsToken(argument, "--image-id") ||
                EqualsToken(argument, "--plugin") ||
                EqualsToken(argument, "--plugin-timeout-seconds"))
            {
                if (index + 1 < args.Count && !IsOption(args[index + 1]))
                {
                    index++;
                }

                continue;
            }

            yield return argument;
        }
    }

    private static CliOutputMode ResolveOutputMode(
        IReadOnlyList<string> args,
        CliOutputMode defaultOutputMode)
    {
        for (var index = 0; index + 1 < args.Count; index++)
        {
            if (EqualsToken(args[index], "--output") &&
                EqualsToken(args[index + 1], "json"))
            {
                return CliOutputMode.Json;
            }
        }

        return defaultOutputMode;
    }

    private static bool IsOption(string? value) =>
        !string.IsNullOrEmpty(value) && value.StartsWith("--", StringComparison.Ordinal);

    private static CliParseResult Failure(CliOutputMode outputMode, string message) =>
        new(null, outputMode, UsageErrorCode, CliValueSanitizer.OneLine(message));
}
