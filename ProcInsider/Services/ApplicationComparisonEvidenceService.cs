using System.IO;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.ApplicationCatalog;

namespace ProcInsider.Services;

public interface IApplicationComparisonEvidenceReader
{
    EvidencePathDiagnostics PathDiagnostics { get; }

    IReadOnlyList<PeAnalysisRecord> GetPeAnalysesForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "");

    IReadOnlyList<AuthenticodeVerificationRecord> GetAuthenticodeVerificationsForProcess(
        string processKey,
        int maxCount = 100,
        string processEntityId = "");
}

public interface IApplicationComparisonEvidenceService
{
    Task<ApplicationComparisonActualContext> LoadAsync(
        ProcessInfo process,
        CancellationToken cancellationToken);
}

public sealed class ApplicationComparisonEvidenceService : IApplicationComparisonEvidenceService
{
    private const int MaximumPeRows = 16;
    private const int MaximumAuthenticodeRows = 16;
    private readonly IApplicationComparisonEvidenceReader _reader;

    public ApplicationComparisonEvidenceService(IApplicationComparisonEvidenceReader reader)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    }

    public async Task<ApplicationComparisonActualContext> LoadAsync(
        ProcessInfo process,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(process);
        cancellationToken.ThrowIfCancellationRequested();

        var processKey = process.GetUniqueKey();
        var processEntityId = process.ProcessEntityId;
        IReadOnlyList<PeAnalysisRecord> analyses = [];
        string peReadFailure = string.Empty;
        IReadOnlyList<AuthenticodeVerificationRecord> authenticodeVerifications = [];
        string authenticodeReadFailure = string.Empty;
        try
        {
            analyses = await Task.Run(
                () => _reader.GetPeAnalysesForProcess(
                    processKey,
                    MaximumPeRows,
                    processEntityId),
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            peReadFailure = $"PE evidence read failed safely: {Bound(ex.Message, 300)}";
        }

        try
        {
            authenticodeVerifications = await Task.Run(
                () => _reader.GetAuthenticodeVerificationsForProcess(
                    processKey,
                    MaximumAuthenticodeRows,
                    processEntityId),
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            authenticodeReadFailure = $"Authenticode evidence read failed safely: {Bound(ex.Message, 300)}";
        }

        cancellationToken.ThrowIfCancellationRequested();
        var latestPe = analyses
            .Where(analysis => analysis.SourceKind == PeAnalysisSourceKind.ProcessImage)
            .OrderByDescending(analysis => analysis.AnalyzedUtc)
            .ThenByDescending(analysis => analysis.AnalysisId, StringComparer.Ordinal)
            .FirstOrDefault();
        var latestAuthenticode = authenticodeVerifications
            .OrderByDescending(verification => verification.VerificationTimeUtc)
            .ThenByDescending(verification => verification.VerificationId, StringComparer.Ordinal)
            .FirstOrDefault();
        var versionInfo = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var peAvailability = ResolvePeAvailability(latestPe, peReadFailure, _reader.PathDiagnostics);
        if (latestPe?.Status == PeAnalysisStatus.Completed)
        {
            try
            {
                versionInfo = JsonSerializer.Deserialize<Dictionary<string, string>>(latestPe.VersionInfoJson)
                    ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                versionInfo = new Dictionary<string, string>(versionInfo, StringComparer.OrdinalIgnoreCase);
            }
            catch (JsonException ex)
            {
                peAvailability = $"Latest process-image PE version metadata is malformed: {Bound(ex.Message, 300)}";
            }
        }

        var identitySource = !string.IsNullOrWhiteSpace(processEntityId)
            ? $"Process projection entity {processEntityId}"
            : $"Process projection exact key {processKey}";
        var peSource = latestPe == null
            ? "Process-image PE analysis"
            : $"PE analysis {latestPe.AnalysisId} at {latestPe.AnalyzedUtc:O}";
        var authenticodeSource = latestAuthenticode == null
            ? "Durable Authenticode verification"
            : $"Authenticode verification {latestAuthenticode.VerificationId} at {latestAuthenticode.VerificationTimeUtc:O}; " +
              $"policy={latestAuthenticode.VerificationPolicy}; sha256={latestAuthenticode.Sha256Hash}";
        var authenticodeAvailability = ResolveAuthenticodeAvailability(
            latestAuthenticode,
            authenticodeReadFailure,
            _reader.PathDiagnostics);
        var filename = ApplicationInfoResolutionService.ResolveExecutableFilename(process);

        var peCompany = GetVersionValue(versionInfo, "CompanyName");
        var peFileDescription = GetVersionValue(versionInfo, "FileDescription");
        return new ApplicationComparisonActualContext
        {
            ProcessEntityId = processEntityId,
            ProcessKey = processKey,
            ExecutableFilename = FromValue(filename, identitySource, "Executable filename is unavailable in the process projection."),
            ProcessPath = FromValue(Clean(process.ProcessPath), identitySource, "Process image path is unavailable or access was denied."),
            OriginalFilename = FromValue(
                GetVersionValue(versionInfo, "OriginalFilename"),
                peSource,
                peAvailability),
            Company = Prefer(
                peCompany,
                peSource,
                Clean(process.CompanyName),
                identitySource,
                "Company metadata is unavailable in both PE analysis and the process projection."),
            Product = FromValue(
                GetVersionValue(versionInfo, "ProductName"),
                peSource,
                peAvailability),
            FileDescription = Prefer(
                peFileDescription,
                peSource,
                Clean(process.FileDescription),
                identitySource,
                "File description is unavailable in both PE analysis and the process projection."),
            ParentProcess = FromValue(
                Clean(process.ParentProcessName),
                identitySource,
                "Parent process is unresolved or unavailable."),
            Account = FromValue(
                Clean(process.UserName),
                identitySource,
                "Process account is unavailable or access was denied."),
            Session = process.SessionId < 0
                ? ApplicationObservedValue.Unavailable(identitySource, "Process session is unavailable.")
                : ApplicationObservedValue.Available(process.SessionId.ToString(System.Globalization.CultureInfo.InvariantCulture), identitySource),
            Privilege = ApplicationObservedValue.Unavailable(
                identitySource,
                "The current durable process projection has no privilege or integrity-level field."),
            CommandLine = FromValue(
                Clean(process.CommandLine),
                identitySource,
                "Command line is unavailable or access was denied."),
            SignerPublisher = latestAuthenticode != null && !string.IsNullOrWhiteSpace(latestAuthenticode.Publisher)
                ? ApplicationObservedValue.Available(latestAuthenticode.Publisher, authenticodeSource)
                : ApplicationObservedValue.Unavailable(authenticodeSource, authenticodeAvailability),
            SignatureKind = latestAuthenticode?.SignatureKind ?? AuthenticodeSignatureKind.Unknown,
            SignatureVerificationStatus = latestAuthenticode?.VerificationStatus ?? AuthenticodeVerificationStatus.Unknown,
            PeAvailability = peAvailability,
            ProcessImageFileSizeBytes = latestPe is { Status: PeAnalysisStatus.Completed, FileSizeBytes: > 0 }
                ? latestPe.FileSizeBytes
                : null
        };
    }

    private static ApplicationObservedValue Prefer(
        string preferred,
        string preferredSource,
        string fallback,
        string fallbackSource,
        string unavailable)
        => !string.IsNullOrWhiteSpace(preferred)
            ? ApplicationObservedValue.Available(preferred, preferredSource)
            : FromValue(fallback, fallbackSource, unavailable);

    private static ApplicationObservedValue FromValue(string value, string source, string unavailable)
        => string.IsNullOrWhiteSpace(value)
            ? ApplicationObservedValue.Unavailable(source, unavailable)
            : ApplicationObservedValue.Available(value, source);

    private static string ResolvePeAvailability(
        PeAnalysisRecord? latestPe,
        string readFailure,
        EvidencePathDiagnostics diagnostics)
    {
        if (!string.IsNullOrWhiteSpace(readFailure))
        {
            return readFailure;
        }

        if (!diagnostics.IsReadable)
        {
            return "PE enrichment is unavailable until a viewer snapshot or archived evidence database is loaded.";
        }

        if (latestPe == null)
        {
            return "No process-image PE analysis is available. Run PE enrichment and Refresh from db when appropriate.";
        }

        if (latestPe.Status == PeAnalysisStatus.Failed)
        {
            var error = string.IsNullOrWhiteSpace(latestPe.ErrorMessage) ? "no failure detail" : latestPe.ErrorMessage;
            return $"Latest process-image PE analysis failed: {Bound(error, 300)}";
        }

        return $"Latest process-image PE analysis is available from {diagnostics.ReadPath} ({latestPe.AnalyzedUtc:O}).";
    }

    private static string ResolveAuthenticodeAvailability(
        AuthenticodeVerificationRecord? latest,
        string readFailure,
        EvidencePathDiagnostics diagnostics)
    {
        if (!string.IsNullOrWhiteSpace(readFailure))
        {
            return readFailure;
        }

        if (!diagnostics.IsReadable)
        {
            return "Authenticode evidence is unavailable until a viewer snapshot or archived evidence database is loaded.";
        }

        if (latest == null)
        {
            return "No Authenticode verification is available. Run PE enrichment and Refresh from db when appropriate.";
        }

        return $"{latest.SignatureKind} signature; verification status {latest.VerificationStatus}; " +
               $"revocation {latest.RevocationStatus} under {latest.VerificationPolicy}.";
    }

    private static string GetVersionValue(IReadOnlyDictionary<string, string> values, string key)
        => values.TryGetValue(key, out var value) ? Clean(value) : string.Empty;

    private static string Clean(string value)
        => string.IsNullOrWhiteSpace(value) || value.StartsWith("<", StringComparison.Ordinal)
            ? string.Empty
            : value.Trim();

    private static string Bound(string value, int maximumLength)
        => value.Length <= maximumLength ? value : $"{value[..maximumLength]}…";
}
