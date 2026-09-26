using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.VisualBasic.FileIO;
using ProcInsider.Compatibility;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class ProcessMonitorService
{
    public const string ProcmonPathEnvironmentVariable = DfiroscopeEnvironmentVariables.ProcessMonitorPath;
    public const string LegacyProcmonPathEnvironmentVariable = DfiroscopeEnvironmentVariables.LegacyProcessMonitorPath;
    private const int DefaultMaxRows = 200000;
    private const int MaximumMaxRows = 1000000;
    private const string SourceName = "Procmon";
    private const string SourceDisplayName = "Sysinternals Process Monitor";

    private readonly InvestigationSessionPaths _sessionPaths;

    public ProcessMonitorService(InvestigationSessionPaths sessionPaths)
    {
        _sessionPaths = sessionPaths;
    }

    public async Task<ProcessMonitorCaptureStartResult> StartCaptureAsync(
        ProcessMonitorCaptureOptions options,
        Guid jobId,
        CancellationToken cancellationToken)
    {
        var procmonPath = ResolveProcmonPath(options.ProcmonPath);
        var outputDirectory = ResolveOutputDirectory(options.OutputDirectory);
        var baseName = $"procmon-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{jobId:N}";
        var backingFilePath = ResolveOutputFile(options.BackingFilePath, outputDirectory, $"{baseName}.pml");
        var csvOutputPath = ResolveOutputFile(options.CsvOutputPath, outputDirectory, $"{baseName}.csv");
        var transcriptPath = ResolveOutputFile(string.Empty, outputDirectory, $"{baseName}.log");

        Directory.CreateDirectory(outputDirectory);
        await AppendTranscriptAsync(transcriptPath, $"Starting Procmon capture with backing file: {backingFilePath}", cancellationToken).ConfigureAwait(false);

        var arguments = new List<string>();
        if (options.AcceptEula)
        {
            arguments.Add("/AcceptEula");
        }

        arguments.Add("/Quiet");
        arguments.Add("/Minimized");
        arguments.Add("/BackingFile");
        arguments.Add(backingFilePath);

        await StartProcmonAsync(procmonPath, arguments, transcriptPath, cancellationToken).ConfigureAwait(false);
        return new ProcessMonitorCaptureStartResult(
            procmonPath,
            outputDirectory,
            backingFilePath,
            csvOutputPath,
            transcriptPath,
            DateTime.UtcNow);
    }

    public async Task<ProcessMonitorImportResult> StopCaptureAndImportAsync(
        ProcessMonitorCaptureStartResult capture,
        int maxRows,
        CancellationToken cancellationToken)
    {
        await AppendTranscriptAsync(capture.TranscriptPath, "Stopping Procmon capture.", CancellationToken.None).ConfigureAwait(false);
        await RunProcmonAsync(
                capture.ProcmonPath,
                ["/Terminate"],
                capture.TranscriptPath,
                TimeSpan.FromSeconds(30),
                CancellationToken.None)
            .ConfigureAwait(false);

        await ExportPmlToCsvAsync(
                capture.ProcmonPath,
                capture.BackingFilePath,
                capture.CsvOutputPath,
                capture.TranscriptPath,
                CancellationToken.None)
            .ConfigureAwait(false);

        return await ImportCsvAsync(
                capture.CsvOutputPath,
                capture.CsvOutputPath,
                capture.CsvOutputPath,
                string.Empty,
                maxRows,
                capture.StartedUtc,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ProcessMonitorImportResult> ImportAsync(
        ProcessMonitorImportOptions options,
        Guid jobId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.InputPath))
        {
            throw new ArgumentException("A Process Monitor CSV or PML path is required.", nameof(options));
        }

        var inputPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(options.InputPath));
        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException($"Process Monitor input file does not exist: {inputPath}", inputPath);
        }

        var outputDirectory = ResolveOutputDirectory(options.OutputDirectory);
        Directory.CreateDirectory(outputDirectory);

        var extension = Path.GetExtension(inputPath);
        var transcriptPath = ResolveOutputFile(
            string.Empty,
            outputDirectory,
            $"procmon-import-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{jobId:N}.log");

        var csvPath = inputPath;
        if (extension.Equals(".pml", StringComparison.OrdinalIgnoreCase))
        {
            var procmonPath = ResolveProcmonPath(options.ProcmonPath);
            csvPath = ResolveOutputFile(
                string.Empty,
                outputDirectory,
                $"{Path.GetFileNameWithoutExtension(inputPath)}-{jobId:N}.csv");
            await ExportPmlToCsvAsync(procmonPath, inputPath, csvPath, transcriptPath, cancellationToken).ConfigureAwait(false);
        }

        return await ImportCsvAsync(
                csvPath,
                inputPath,
                csvPath,
                options.CaptureId,
                options.MaxRows,
                File.GetLastWriteTimeUtc(inputPath),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task ExportPmlToCsvAsync(
        string procmonPath,
        string pmlPath,
        string csvPath,
        string transcriptPath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(pmlPath))
        {
            throw new FileNotFoundException($"Process Monitor PML file does not exist: {pmlPath}", pmlPath);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(csvPath) ?? _sessionPaths.ProcessMonitorDirectory);
        await AppendTranscriptAsync(transcriptPath, $"Exporting Procmon PML to CSV: {pmlPath} -> {csvPath}", cancellationToken).ConfigureAwait(false);
        var result = await RunProcmonAsync(
                procmonPath,
                ["/AcceptEula", "/Quiet", "/OpenLog", pmlPath, "/SaveAs", csvPath],
                transcriptPath,
                TimeSpan.FromMinutes(10),
                cancellationToken)
            .ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"Procmon CSV export failed with exit code {result.ExitCode}: {FirstNonEmpty(result.StandardError, result.StandardOutput, "<no output>")}");
        }

        if (!File.Exists(csvPath) || new FileInfo(csvPath).Length == 0)
        {
            throw new InvalidOperationException($"Procmon did not create a readable CSV export: {csvPath}");
        }
    }

    private async Task<ProcessMonitorImportResult> ImportCsvAsync(
        string csvPath,
        string sourcePath,
        string generatedCsvPath,
        string captureId,
        int maxRows,
        DateTime defaultTimestampUtc,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(csvPath))
        {
            throw new FileNotFoundException($"Process Monitor CSV file does not exist: {csvPath}", csvPath);
        }

        var parsed = await Task.Run(
                () => ReadProcmonCsv(csvPath, ClampMaxRows(maxRows), defaultTimestampUtc, cancellationToken),
                cancellationToken)
            .ConfigureAwait(false);

        if (parsed.Rows.Count == 0)
        {
            return new ProcessMonitorImportResult(
                sourcePath,
                generatedCsvPath,
                parsed.TotalRows,
                parsed.FailedRows,
                [],
                []);
        }

        var effectiveCaptureId = string.IsNullOrWhiteSpace(captureId)
            ? $"procmon-import-{HashShort(Path.GetFullPath(sourcePath))}"
            : captureId.Trim();

        var groups = parsed.Rows
            .GroupBy(row => row.ProcessIdentityKey, StringComparer.Ordinal)
            .ToList();
        var processKeys = groups.ToDictionary(
            group => group.Key,
            group => BuildProcessKey(group.Key, group.Min(row => row.TimestampUtc)),
            StringComparer.Ordinal);

        var processes = groups
            .Select(group => CreateProcessRecord(group.ToList(), processKeys[group.Key], effectiveCaptureId))
            .ToList();
        var events = parsed.Rows
            .Select(row => CreateEventRecord(row, processKeys[row.ProcessIdentityKey], effectiveCaptureId, csvPath))
            .ToList();

        return new ProcessMonitorImportResult(
            sourcePath,
            generatedCsvPath,
            parsed.TotalRows,
            parsed.FailedRows,
            processes,
            events);
    }

    private static ProcmonCsvReadResult ReadProcmonCsv(
        string csvPath,
        int maxRows,
        DateTime defaultTimestampUtc,
        CancellationToken cancellationToken)
    {
        using var parser = new TextFieldParser(csvPath, Encoding.UTF8, detectEncoding: true)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true,
            TrimWhiteSpace = false
        };
        parser.SetDelimiters(",");

        var headers = parser.ReadFields();
        if (headers == null || headers.Length == 0)
        {
            throw new InvalidDataException("Process Monitor CSV did not contain a header row.");
        }

        var headerMap = BuildHeaderMap(headers);
        var rows = new List<ProcmonCsvRow>();
        var failedRows = 0;
        var totalRows = 0;
        var defaultLocalDate = defaultTimestampUtc == default
            ? File.GetLastWriteTime(csvPath).Date
            : defaultTimestampUtc.ToLocalTime().Date;

        while (!parser.EndOfData && rows.Count < maxRows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string[]? fields;
            try
            {
                fields = parser.ReadFields();
            }
            catch (MalformedLineException)
            {
                failedRows++;
                continue;
            }

            if (fields == null || fields.Length == 0)
            {
                continue;
            }

            totalRows++;
            try
            {
                rows.Add(CreateCsvRow(fields, headerMap, totalRows, defaultLocalDate));
            }
            catch
            {
                failedRows++;
            }
        }

        return new ProcmonCsvReadResult(rows, totalRows, failedRows);
    }

    private static ProcmonCsvRow CreateCsvRow(
        string[] fields,
        IReadOnlyDictionary<string, int> headerMap,
        int rowNumber,
        DateTime defaultLocalDate)
    {
        var processName = FirstNonEmpty(
            GetField(fields, headerMap, "Process Name", "ProcessName", "Process"),
            "<unknown>");
        var pid = ParseInt(GetField(fields, headerMap, "PID", "Process ID"));
        var imagePath = GetField(fields, headerMap, "Image Path", "ImagePath", "Path to Image");
        var commandLine = GetField(fields, headerMap, "Command Line", "CommandLine");
        var operation = GetField(fields, headerMap, "Operation");
        var path = GetField(fields, headerMap, "Path", "Target");
        var result = GetField(fields, headerMap, "Result");
        var detail = GetField(fields, headerMap, "Detail", "Details");
        var timestampUtc = ParseTimestamp(
            GetField(fields, headerMap, "Date & Time", "Date/Time", "Timestamp", "Time of Day", "Time"),
            defaultLocalDate);
        var identityMaterial = string.Join(
            "|",
            pid.ToString(CultureInfo.InvariantCulture),
            NormalizeIdentity(processName),
            NormalizeIdentity(imagePath),
            NormalizeIdentity(commandLine));
        if (pid <= 0 && string.IsNullOrWhiteSpace(processName))
        {
            identityMaterial = $"row:{rowNumber}:{HashShort(string.Join("|", fields))}";
        }

        return new ProcmonCsvRow(
            rowNumber,
            timestampUtc,
            identityMaterial,
            processName,
            pid,
            ParseInt(GetField(fields, headerMap, "Parent PID", "Parent Process ID", "PPID")),
            operation,
            path,
            result,
            detail,
            GetField(fields, headerMap, "Event Class", "EventClass"),
            GetField(fields, headerMap, "Category"),
            imagePath,
            GetField(fields, headerMap, "Company", "Company Name"),
            GetField(fields, headerMap, "Description", "File Description"),
            GetField(fields, headerMap, "Version"),
            GetField(fields, headerMap, "User", "User Name"),
            commandLine,
            GetField(fields, headerMap, "Architecture"),
            GetField(fields, headerMap, "TID", "Thread ID"),
            fields);
    }

    private static ProcessRecord CreateProcessRecord(
        IReadOnlyList<ProcmonCsvRow> rows,
        string processKey,
        string captureId)
    {
        var first = rows.OrderBy(row => row.TimestampUtc).First();
        var last = rows.OrderByDescending(row => row.TimestampUtc).First();
        var exit = rows
            .Where(row => row.Operation.Contains("Process Exit", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(row => row.TimestampUtc)
            .FirstOrDefault();

        return new ProcessRecord
        {
            CaptureId = captureId,
            ProcessKey = processKey,
            ProcessId = first.ProcessId,
            StartTimeUtc = null,
            EndTimeUtc = exit?.TimestampUtc,
            Status = exit == null ? ProcessStatus.NotFound : ProcessStatus.Exited,
            ParentProcessId = FirstNonZero(rows.Select(row => row.ParentProcessId)),
            ParentProcessName = "<unknown>",
            ProcessName = FirstNonEmpty(first.ProcessName, "<unknown>"),
            ProcessPath = FirstNonEmpty(FirstNonEmpty(rows.Select(row => row.ImagePath)), "<not available>"),
            CommandLine = FirstNonEmpty(FirstNonEmpty(rows.Select(row => row.CommandLine)), "<not available>"),
            UserName = FirstNonEmpty(FirstNonEmpty(rows.Select(row => row.User)), "<not available>"),
            Architecture = FirstNonEmpty(FirstNonEmpty(rows.Select(row => row.Architecture)), "<not available>"),
            CompanyName = FirstNonEmpty(FirstNonEmpty(rows.Select(row => row.Company)), "<not available>"),
            FileDescription = FirstNonEmpty(FirstNonEmpty(rows.Select(row => row.Description)), "<not available>"),
            Sha256Hash = "<not available>",
            FirstObservedUtc = rows.Min(row => row.TimestampUtc),
            LastObservedUtc = rows.Max(row => row.TimestampUtc),
            LastSource = "ProcessMonitorCsvImport"
        };
    }

    private static TelemetryEventRecord CreateEventRecord(
        ProcmonCsvRow row,
        string processKey,
        string captureId,
        string csvPath)
    {
        var (category, action) = MapOperation(row.Operation, row.EventClass, row.Category);
        return new TelemetryEventRecord
        {
            CaptureId = captureId,
            TimestampUtc = row.TimestampUtc,
            Source = SourceName,
            ProcessKey = processKey,
            ProcessId = row.ProcessId,
            ProcessName = FirstNonEmpty(row.ProcessName, "<unknown>"),
            ParentProcessId = row.ParentProcessId,
            Category = category,
            Action = action,
            Target = row.Path,
            Summary = BuildSummary(row),
            Details = BuildDetails(row),
            RiskFlags = BuildRiskFlags(row, action),
            IsInteresting = IsInteresting(row, action),
            RepeatCount = 1,
            RawProvider = SourceDisplayName,
            RawLogName = csvPath,
            RawRecordId = row.RowNumber.ToString(CultureInfo.InvariantCulture),
            CorrelationMethod = "ProcmonCsvSyntheticProcessKey"
        };
    }

    private static (ProcessEventCategory Category, ProcessEventAction Action) MapOperation(
        string operation,
        string eventClass,
        string category)
    {
        var operationValue = operation.Trim();
        var classValue = FirstNonEmpty(eventClass, category);
        if (operationValue.Contains("Process Create", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.Process, ProcessEventAction.ProcessStart);
        }

        if (operationValue.Contains("Process Exit", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.Process, ProcessEventAction.ProcessExit);
        }

        if (operationValue.Contains("Load Image", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.Process, ProcessEventAction.ImageLoad);
        }

        if (operationValue.StartsWith("Reg", StringComparison.OrdinalIgnoreCase) ||
            classValue.Contains("Registry", StringComparison.OrdinalIgnoreCase))
        {
            if (operationValue.Contains("Delete", StringComparison.OrdinalIgnoreCase))
            {
                return (ProcessEventCategory.Registry, operationValue.Contains("Value", StringComparison.OrdinalIgnoreCase)
                    ? ProcessEventAction.RegistryDeleteValue
                    : ProcessEventAction.RegistryDeleteKey);
            }

            if (operationValue.Contains("Set", StringComparison.OrdinalIgnoreCase) ||
                operationValue.Contains("Write", StringComparison.OrdinalIgnoreCase))
            {
                return (ProcessEventCategory.Registry, ProcessEventAction.RegistrySetValue);
            }

            if (operationValue.Contains("Rename", StringComparison.OrdinalIgnoreCase))
            {
                return (ProcessEventCategory.Registry, operationValue.Contains("Value", StringComparison.OrdinalIgnoreCase)
                    ? ProcessEventAction.RegistryRenameValue
                    : ProcessEventAction.RegistryRenameKey);
            }

            return (ProcessEventCategory.Registry, ProcessEventAction.RegistryCreateKey);
        }

        if (operationValue.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) ||
            operationValue.StartsWith("UDP", StringComparison.OrdinalIgnoreCase) ||
            classValue.Contains("Network", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.Network, ProcessEventAction.Connect);
        }

        if (operationValue.Contains("WriteFile", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.File, ProcessEventAction.FileWrite);
        }

        if (operationValue.Contains("Rename", StringComparison.OrdinalIgnoreCase) ||
            operationValue.Contains("SetRenameInformation", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.File, ProcessEventAction.FileRename);
        }

        if (operationValue.Contains("Delete", StringComparison.OrdinalIgnoreCase) ||
            operationValue.Contains("SetDispositionInformation", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.File, ProcessEventAction.FileDelete);
        }

        if (operationValue.Contains("CreateFile", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.File, ProcessEventAction.FileCreate);
        }

        if (operationValue.Contains("ReadFile", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.File, ProcessEventAction.RawAccessRead);
        }

        if (classValue.Contains("File", StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessEventCategory.File, ProcessEventAction.WindowsEvent);
        }

        return (ProcessEventCategory.Windows, ProcessEventAction.WindowsEvent);
    }

    private static string BuildSummary(ProcmonCsvRow row)
    {
        var target = string.IsNullOrWhiteSpace(row.Path) ? "<no target>" : row.Path;
        var result = string.IsNullOrWhiteSpace(row.Result) ? string.Empty : $" [{row.Result}]";
        return $"Procmon {FirstNonEmpty(row.Operation, "event")}{result}: {target}";
    }

    private static string BuildDetails(ProcmonCsvRow row)
    {
        var values = new Dictionary<string, string>
        {
            ["Row"] = row.RowNumber.ToString(CultureInfo.InvariantCulture),
            ["TimestampUtc"] = row.TimestampUtc.ToString("O"),
            ["Process"] = row.ProcessName,
            ["PID"] = row.ProcessId.ToString(CultureInfo.InvariantCulture),
            ["ParentPID"] = row.ParentProcessId.ToString(CultureInfo.InvariantCulture),
            ["Operation"] = row.Operation,
            ["Path"] = row.Path,
            ["Result"] = row.Result,
            ["Detail"] = row.Detail,
            ["EventClass"] = row.EventClass,
            ["Category"] = row.Category,
            ["ImagePath"] = row.ImagePath,
            ["CommandLine"] = row.CommandLine,
            ["User"] = row.User,
            ["Architecture"] = row.Architecture,
            ["ThreadId"] = row.ThreadId,
            ["ProcessIdentityNote"] = $"Procmon CSV does not always include process start time; {ProductIdentity.DisplayName} uses a Procmon import process key derived from PID, process metadata, and first observed timestamp."
        };

        return JsonSerializer.Serialize(values
            .Where(pair => !string.IsNullOrWhiteSpace(pair.Value))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));
    }

    private static string BuildRiskFlags(ProcmonCsvRow row, ProcessEventAction action)
    {
        var flags = new List<string>();
        if (row.Result.Contains("ACCESS DENIED", StringComparison.OrdinalIgnoreCase))
        {
            flags.Add("ProcmonAccessDenied");
        }

        if (action is ProcessEventAction.ProcessStart or ProcessEventAction.ProcessExit or ProcessEventAction.ImageLoad)
        {
            flags.Add("ProcmonProcessActivity");
        }

        if (action is ProcessEventAction.RegistrySetValue or ProcessEventAction.RegistryDeleteKey or ProcessEventAction.RegistryDeleteValue)
        {
            flags.Add("ProcmonRegistryWrite");
        }

        if (action is ProcessEventAction.FileWrite or ProcessEventAction.FileDelete or ProcessEventAction.FileRename)
        {
            flags.Add("ProcmonFileWrite");
        }

        return string.Join(",", flags);
    }

    private static bool IsInteresting(ProcmonCsvRow row, ProcessEventAction action)
    {
        return !string.IsNullOrWhiteSpace(BuildRiskFlags(row, action)) ||
               row.Result.Contains("DENIED", StringComparison.OrdinalIgnoreCase) ||
               row.Result.Contains("ERROR", StringComparison.OrdinalIgnoreCase);
    }

    private async Task StartProcmonAsync(
        string procmonPath,
        IReadOnlyList<string> arguments,
        string transcriptPath,
        CancellationToken cancellationToken)
    {
        await AppendTranscriptAsync(transcriptPath, $"Command: {Quote(procmonPath)} {string.Join(" ", arguments.Select(Quote))}", cancellationToken).ConfigureAwait(false);
        using var process = Process.Start(CreateProcessStartInfo(procmonPath, arguments, redirectOutput: false));
        if (process == null)
        {
            throw new InvalidOperationException("Procmon did not start.");
        }

        var delay = Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
        var exit = process.WaitForExitAsync(cancellationToken);
        var completed = await Task.WhenAny(exit, delay).ConfigureAwait(false);
        if (completed == exit)
        {
            await exit.ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"Procmon exited during startup with code {process.ExitCode}.");
            }

            await AppendTranscriptAsync(transcriptPath, "Procmon startup command exited successfully.", cancellationToken).ConfigureAwait(false);
            return;
        }

        await AppendTranscriptAsync(transcriptPath, $"Procmon process {process.Id} is still running after startup.", cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ProcessRunResult> RunProcmonAsync(
        string procmonPath,
        IReadOnlyList<string> arguments,
        string transcriptPath,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        await AppendTranscriptAsync(transcriptPath, $"Command: {Quote(procmonPath)} {string.Join(" ", arguments.Select(Quote))}", cancellationToken).ConfigureAwait(false);
        using var process = new Process
        {
            StartInfo = CreateProcessStartInfo(procmonPath, arguments, redirectOutput: true),
            EnableRaisingEvents = true
        };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                stdout.AppendLine(e.Data);
            }
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                stderr.AppendLine(e.Data);
            }
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("Procmon did not start.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var waitTask = process.WaitForExitAsync(timeoutCts.Token);
        var completed = await Task.WhenAny(waitTask, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
        if (completed != waitTask)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            throw new TimeoutException($"Procmon command did not complete within {timeout}.");
        }

        await waitTask.ConfigureAwait(false);
        var result = new ProcessRunResult(process.ExitCode, stdout.ToString(), stderr.ToString());
        await AppendTranscriptAsync(
                transcriptPath,
                $"ExitCode: {result.ExitCode}{Environment.NewLine}Stdout:{Environment.NewLine}{result.StandardOutput}{Environment.NewLine}Stderr:{Environment.NewLine}{result.StandardError}",
                cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    private static ProcessStartInfo CreateProcessStartInfo(
        string fileName,
        IReadOnlyList<string> arguments,
        bool redirectOutput)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = redirectOutput,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private string ResolveProcmonPath(string requestedPath)
    {
        var environmentPath = ResolveEnvironmentPath();
        var candidates = new List<string>();
        AddCandidate(candidates, requestedPath);
        AddCandidate(candidates, environmentPath.Value);
        AddCandidate(candidates, FindExecutableOnPath("Procmon64.exe"));
        AddCandidate(candidates, FindExecutableOnPath("Procmon.exe"));

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        AddCandidate(candidates, Path.Combine(programFiles, "Sysinternals", "Procmon64.exe"));
        AddCandidate(candidates, Path.Combine(programFiles, "Sysinternals", "Procmon.exe"));
        AddCandidate(candidates, Path.Combine(programFilesX86, "Sysinternals", "Procmon.exe"));

        var path = candidates.FirstOrDefault(File.Exists);
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new FileNotFoundException(
                $"Procmon.exe was not found. Select a Procmon path in the GUI, put Procmon.exe/Procmon64.exe on PATH, " +
                $"or set {ProcmonPathEnvironmentVariable}. The legacy {LegacyProcmonPathEnvironmentVariable} alias remains supported. " +
                environmentPath.Diagnostic);
        }

        return Path.GetFullPath(path);
    }

    public static EnvironmentVariableResolution ResolveEnvironmentPath() =>
        EnvironmentVariableCompatibility.Resolve(
            ProcmonPathEnvironmentVariable,
            LegacyProcmonPathEnvironmentVariable);

    private string ResolveOutputDirectory(string requestedDirectory)
    {
        var directory = string.IsNullOrWhiteSpace(requestedDirectory)
            ? _sessionPaths.ProcessMonitorDirectory
            : Environment.ExpandEnvironmentVariables(requestedDirectory);
        return Path.GetFullPath(directory);
    }

    private static string ResolveOutputFile(string requestedPath, string outputDirectory, string defaultFileName)
    {
        var path = string.IsNullOrWhiteSpace(requestedPath)
            ? Path.Combine(outputDirectory, defaultFileName)
            : Environment.ExpandEnvironmentVariables(requestedPath);
        return Path.GetFullPath(path);
    }

    private static void AddCandidate(List<string> candidates, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            candidates.Add(Path.GetFullPath(Environment.ExpandEnvironmentVariables(value)));
        }
    }

    private static string? FindExecutableOnPath(string fileName)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(Environment.ExpandEnvironmentVariables(directory.Trim()), fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch
            {
            }
        }

        return null;
    }

    private static Dictionary<string, int> BuildHeaderMap(IReadOnlyList<string> headers)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < headers.Count; index++)
        {
            var key = NormalizeHeader(headers[index]);
            if (!string.IsNullOrWhiteSpace(key) && !map.ContainsKey(key))
            {
                map[key] = index;
            }
        }

        return map;
    }

    private static string GetField(string[] fields, IReadOnlyDictionary<string, int> headerMap, params string[] aliases)
    {
        foreach (var alias in aliases)
        {
            if (headerMap.TryGetValue(NormalizeHeader(alias), out var index) && index >= 0 && index < fields.Length)
            {
                return fields[index]?.Trim() ?? string.Empty;
            }
        }

        return string.Empty;
    }

    private static string NormalizeHeader(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch))
            {
                builder.Append(char.ToUpperInvariant(ch));
            }
        }

        return builder.ToString();
    }

    private static string NormalizeIdentity(string value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToUpperInvariant();

    private static DateTime ParseTimestamp(string value, DateTime defaultLocalDate)
    {
        if (DateTimeOffset.TryParse(
                value,
                CultureInfo.CurrentCulture,
                DateTimeStyles.AssumeLocal | DateTimeStyles.AllowWhiteSpaces,
                out var offset) ||
            DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal | DateTimeStyles.AllowWhiteSpaces,
                out offset))
        {
            var parsedLocal = offset.LocalDateTime;
            if (LooksLikeTimeOnly(value))
            {
                parsedLocal = defaultLocalDate.Date.Add(parsedLocal.TimeOfDay);
            }

            return parsedLocal.ToUniversalTime();
        }

        if (TimeSpan.TryParse(value, CultureInfo.CurrentCulture, out var time) ||
            TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out time))
        {
            return defaultLocalDate.Date.Add(time).ToUniversalTime();
        }

        return DateTime.UtcNow;
    }

    private static bool LooksLikeTimeOnly(string value)
        => !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsLetterOrDigit)
            ? false
            : !value.Contains('/', StringComparison.Ordinal) &&
              !value.Contains('-', StringComparison.Ordinal) &&
              !value.Contains(',', StringComparison.Ordinal);

    private static int ParseInt(string value)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ||
           int.TryParse(value, NumberStyles.Integer, CultureInfo.CurrentCulture, out result)
            ? result
            : 0;

    private static int FirstNonZero(IEnumerable<int> values)
        => values.FirstOrDefault(value => value != 0);

    private static string FirstNonEmpty(IEnumerable<string> values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string FirstNonEmpty(params string[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string BuildProcessKey(string identityKey, DateTime firstObservedUtc)
        => $"procmon:{firstObservedUtc.Ticks}:{HashShort(identityKey)}";

    private static string HashShort(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }

    private static int ClampMaxRows(int maxRows)
        => Math.Clamp(maxRows <= 0 ? DefaultMaxRows : maxRows, 1, MaximumMaxRows);

    private static string Quote(string value)
        => value.Contains(' ', StringComparison.Ordinal) ? $"\"{value}\"" : value;

    private static async Task AppendTranscriptAsync(string transcriptPath, string text, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(transcriptPath) ?? AppContext.BaseDirectory);
        await File.AppendAllTextAsync(
                transcriptPath,
                $"[{DateTimeOffset.UtcNow:O}] {text}{Environment.NewLine}",
                cancellationToken)
            .ConfigureAwait(false);
    }

    private sealed record ProcmonCsvReadResult(
        IReadOnlyList<ProcmonCsvRow> Rows,
        int TotalRows,
        int FailedRows);

    private sealed record ProcmonCsvRow(
        int RowNumber,
        DateTime TimestampUtc,
        string ProcessIdentityKey,
        string ProcessName,
        int ProcessId,
        int ParentProcessId,
        string Operation,
        string Path,
        string Result,
        string Detail,
        string EventClass,
        string Category,
        string ImagePath,
        string Company,
        string Description,
        string Version,
        string User,
        string CommandLine,
        string Architecture,
        string ThreadId,
        IReadOnlyList<string> RawFields);

    private sealed record ProcessRunResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);
}

public sealed record ProcessMonitorCaptureOptions
{
    public string ProcmonPath { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string OutputDirectory { get; init; } = string.Empty;
    public string BackingFilePath { get; init; } = string.Empty;
    public string CsvOutputPath { get; init; } = string.Empty;
    public bool AcceptEula { get; init; } = true;
    public int MaxRows { get; init; } = 200000;
}

public sealed record ProcessMonitorImportOptions
{
    public string InputPath { get; init; } = string.Empty;
    public string ProcmonPath { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string OutputDirectory { get; init; } = string.Empty;
    public int MaxRows { get; init; } = 200000;
}

public sealed record ProcessMonitorCaptureStartResult(
    string ProcmonPath,
    string OutputDirectory,
    string BackingFilePath,
    string CsvOutputPath,
    string TranscriptPath,
    DateTime StartedUtc);

public sealed record ProcessMonitorImportResult(
    string SourcePath,
    string CsvPath,
    int TotalRows,
    int FailedRows,
    IReadOnlyList<ProcessRecord> Processes,
    IReadOnlyList<TelemetryEventRecord> Events);
