using System.IO;
using System.Text.RegularExpressions;
using ProcInsider.Models;
using ProcInsider.Models.ApplicationCatalog;
using ProcInsider.Models.Telemetry;

namespace ProcInsider.Services;

public sealed class ApplicationProfileComparisonService
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(150);

    public ApplicationComparisonReport Compare(
        ApplicationMetadataRecord resolvedMetadata,
        ApplicationProfileDefinition? catalogProfile,
        ApplicationComparisonActualContext actual,
        IReadOnlyList<ApplicationCatalogMatch> candidates,
        string selectionReason)
    {
        ArgumentNullException.ThrowIfNull(resolvedMetadata);
        ArgumentNullException.ThrowIfNull(actual);
        candidates ??= [];

        var expectedSource = catalogProfile == null
            ? $"{resolvedMetadata.RecordOrigin} application metadata"
            : $"Application catalog profile {catalogProfile.ProfileId} revision {catalogProfile.ProfileRevision}";
        var rows = new List<ApplicationComparisonRow>
        {
            CompareFilename(resolvedMetadata, catalogProfile, actual.ExecutableFilename, expectedSource),
            ComparePath(ResolveValues(resolvedMetadata, resolvedMetadata.PathPattern, catalogProfile?.Discriminators.PathPatterns), actual.ProcessPath, expectedSource),
            CompareExactValues(
                ApplicationComparisonPropertyKind.OriginalFilename,
                catalogProfile?.Discriminators.OriginalFilenames ?? [],
                actual.OriginalFilename,
                ApplicationComparisonImportance.High,
                expectedSource,
                filenameSemantics: true,
                matchRationale: "Latest PE OriginalFilename is consistent with the selected profile, even if the current image name differs."),
            CompareExactValues(
                ApplicationComparisonPropertyKind.Company,
                ResolveValues(resolvedMetadata, resolvedMetadata.CompanyVendor, catalogProfile?.Discriminators.Companies),
                actual.Company,
                ApplicationComparisonImportance.Medium,
                expectedSource),
            CompareExactValues(
                ApplicationComparisonPropertyKind.Product,
                ResolveValues(resolvedMetadata, resolvedMetadata.ProductName, catalogProfile?.Discriminators.Products),
                actual.Product,
                ApplicationComparisonImportance.Medium,
                expectedSource),
            CompareExactValues(
                ApplicationComparisonPropertyKind.FileDescription,
                catalogProfile?.Discriminators.FileDescriptions ?? [],
                actual.FileDescription,
                ApplicationComparisonImportance.Low,
                expectedSource),
            CompareExactValues(
                ApplicationComparisonPropertyKind.ParentProcess,
                catalogProfile?.ExpectedContext.ParentExecutables ?? [],
                actual.ParentProcess,
                ApplicationComparisonImportance.High,
                expectedSource,
                filenameSemantics: true),
            CompareAccount(catalogProfile?.ExpectedContext.Accounts ?? [], actual.Account, expectedSource),
            CompareSession(catalogProfile?.ExpectedContext.Sessions ?? [], actual.Session, expectedSource),
            CompareExactValues(
                ApplicationComparisonPropertyKind.Privilege,
                catalogProfile?.ExpectedContext.PrivilegeLevels ?? [],
                actual.Privilege,
                ApplicationComparisonImportance.Medium,
                expectedSource),
            CompareCommandLine(resolvedMetadata, catalogProfile, actual.CommandLine, expectedSource),
            CompareSignerPublisher(
                resolvedMetadata,
                catalogProfile,
                actual.SignerPublisher,
                actual.SignatureKind,
                actual.SignatureVerificationStatus,
                expectedSource)
        };

        var selectedProfileDisplay = catalogProfile == null
            ? $"{resolvedMetadata.DisplayName} ({resolvedMetadata.RecordOrigin}; no linked built-in profile)"
            : $"{catalogProfile.DisplayName} ({catalogProfile.ProfileId}, revision {catalogProfile.ProfileRevision})";
        return new ApplicationComparisonReport
        {
            SelectedProfileDisplay = selectedProfileDisplay,
            SelectionReason = selectionReason,
            CandidateSummary = FormatCandidates(candidates, catalogProfile?.ProfileId),
            HasAmbiguousCandidates = candidates.Count > 1,
            Rows = rows
        };
    }

    private static ApplicationComparisonRow CompareFilename(
        ApplicationMetadataRecord metadata,
        ApplicationProfileDefinition? catalogProfile,
        ApplicationObservedValue actual,
        string expectedSource)
    {
        var matcher = metadata.RecordOrigin == ApplicationProfileOrigin.BuiltInCatalog && catalogProfile != null
            ? catalogProfile.Filename
            : new ApplicationFilenameMatcher
            {
                Kind = metadata.IsRegexPattern ? ApplicationFilenameMatchKind.Regex : ApplicationFilenameMatchKind.Exact,
                Pattern = metadata.ExecutableNamePattern
            };
        var expected = matcher.Pattern?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(expected))
        {
            return NotApplicable(
                ApplicationComparisonPropertyKind.ExecutableFilename,
                ApplicationComparisonOperator.NormalizedFilename,
                ApplicationComparisonImportance.Critical,
                "No executable filename expectation is defined.",
                actual,
                expectedSource);
        }

        if (!actual.IsAvailable)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.ExecutableFilename,
                ApplicationComparisonOperator.NormalizedFilename,
                ApplicationComparisonImportance.Critical,
                expected,
                actual,
                "The executable filename cannot be evaluated because the actual value is unavailable.");
        }

        try
        {
            var matched = matcher.Kind == ApplicationFilenameMatchKind.Exact
                ? string.Equals(
                    NormalizeComparableExecutableFilename(expected),
                    NormalizeComparableExecutableFilename(actual.Value),
                    StringComparison.Ordinal)
                : Regex.IsMatch(
                    ApplicationPatternValidator.NormalizeFilename(actual.Value),
                    expected,
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                    RegexTimeout);
            return Result(
                ApplicationComparisonPropertyKind.ExecutableFilename,
                ApplicationComparisonOperator.NormalizedFilename,
                ApplicationComparisonImportance.Critical,
                expected,
                actual,
                matched,
                matched
                    ? "The normalized filename is consistent with the selected profile; this does not prove legitimacy."
                    : "The normalized filename differs from the selected profile. Profile selection and conformity remain separate decisions.");
        }
        catch (Exception ex) when (ex is ArgumentException or RegexMatchTimeoutException)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.ExecutableFilename,
                ApplicationComparisonOperator.NormalizedFilename,
                ApplicationComparisonImportance.Critical,
                expected,
                actual,
                $"The saved filename regex could not be evaluated safely: {ex.Message}");
        }
    }

    private static ApplicationComparisonRow ComparePath(
        IReadOnlyList<string> expected,
        ApplicationObservedValue actual,
        string expectedSource)
    {
        if (expected.Count == 0)
        {
            return NotApplicable(
                ApplicationComparisonPropertyKind.ProcessPath,
                ApplicationComparisonOperator.PathPatternAny,
                ApplicationComparisonImportance.Critical,
                "No expected path pattern is defined.",
                actual,
                expectedSource);
        }

        if (!actual.IsAvailable)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.ProcessPath,
                ApplicationComparisonOperator.PathPatternAny,
                ApplicationComparisonImportance.Critical,
                FormatExpected(expected),
                actual,
                "The process path is unavailable or access was denied; absence is not a mismatch.");
        }

        var matched = expected.Any(pattern => PathMatches(actual.Value, pattern));
        return Result(
            ApplicationComparisonPropertyKind.ProcessPath,
            ApplicationComparisonOperator.PathPatternAny,
            ApplicationComparisonImportance.Critical,
            FormatExpected(expected),
            actual,
            matched,
            matched
                ? "The observed path matches an allowed profile pattern; this is one consistency signal, not a benign verdict."
                : "The selected filename profile is retained, but the image path matches no allowed pattern. This is an analyst pivot, not an automatic malware verdict.");
    }

    private static ApplicationComparisonRow CompareExactValues(
        ApplicationComparisonPropertyKind kind,
        IReadOnlyList<string> expected,
        ApplicationObservedValue actual,
        ApplicationComparisonImportance importance,
        string expectedSource,
        bool filenameSemantics = false,
        string? matchRationale = null)
    {
        if (expected.Count == 0)
        {
            return NotApplicable(
                kind,
                ApplicationComparisonOperator.ExactValueAny,
                importance,
                "The selected profile defines no machine-comparable expectation for this property.",
                actual,
                expectedSource);
        }

        if (!actual.IsAvailable)
        {
            return Unknown(
                kind,
                ApplicationComparisonOperator.ExactValueAny,
                importance,
                FormatExpected(expected),
                actual,
                "The actual value is unavailable; missing or unavailable evidence remains Unknown.");
        }

        var actualNormalized = filenameSemantics
            ? NormalizeComparableExecutableFilename(actual.Value)
            : NormalizeValue(actual.Value);
        var matched = expected.Any(value => string.Equals(
            filenameSemantics ? NormalizeComparableExecutableFilename(value) : NormalizeValue(value),
            actualNormalized,
            StringComparison.Ordinal));
        return Result(
            kind,
            ApplicationComparisonOperator.ExactValueAny,
            importance,
            FormatExpected(expected),
            actual,
            matched,
            matched
                ? matchRationale ?? (filenameSemantics
                    ? "The observed executable filename is consistent with one expected profile value; a terminal .exe suffix is treated as optional notation."
                    : "The observed value is consistent with one expected profile value.")
                : "The observed value differs from every explicit expected profile value.");
    }

    private static ApplicationComparisonRow CompareAccount(
        IReadOnlyList<string> expected,
        ApplicationObservedValue actual,
        string expectedSource)
    {
        if (expected.Count == 0)
        {
            return NotApplicable(
                ApplicationComparisonPropertyKind.Account,
                ApplicationComparisonOperator.AccountContext,
                ApplicationComparisonImportance.High,
                "No expected account context is defined.",
                actual,
                expectedSource);
        }

        if (!actual.IsAvailable)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.Account,
                ApplicationComparisonOperator.AccountContext,
                ApplicationComparisonImportance.High,
                FormatExpected(expected),
                actual,
                "The account is unavailable or access was denied; absence is not a mismatch.");
        }

        var actualAccount = NormalizeAccount(actual.Value);
        var comparable = expected
            .Select(MapExpectedAccount)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
        if (comparable.Count == 0)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.Account,
                ApplicationComparisonOperator.AccountContext,
                ApplicationComparisonImportance.High,
                FormatExpected(expected),
                actual,
                "The profile account text is descriptive rather than a concrete account identifier, so deterministic conformity is unavailable.");
        }

        var matched = comparable.Contains(actualAccount, StringComparer.Ordinal);
        return Result(
            ApplicationComparisonPropertyKind.Account,
            ApplicationComparisonOperator.AccountContext,
            ApplicationComparisonImportance.High,
            FormatExpected(expected),
            actual,
            matched,
            matched
                ? "The normalized process account matches an explicit expected service-account identity."
                : "The normalized process account differs from every explicit expected service-account identity.");
    }

    private static ApplicationComparisonRow CompareSession(
        IReadOnlyList<string> expected,
        ApplicationObservedValue actual,
        string expectedSource)
    {
        if (expected.Count == 0)
        {
            return NotApplicable(
                ApplicationComparisonPropertyKind.Session,
                ApplicationComparisonOperator.SessionContext,
                ApplicationComparisonImportance.Medium,
                "No expected session context is defined.",
                actual,
                expectedSource);
        }

        if (!actual.IsAvailable || !int.TryParse(actual.Value, out var sessionId))
        {
            return Unknown(
                ApplicationComparisonPropertyKind.Session,
                ApplicationComparisonOperator.SessionContext,
                ApplicationComparisonImportance.Medium,
                FormatExpected(expected),
                actual,
                "The process session is unavailable; absence is not a mismatch.");
        }

        var recognized = false;
        var matched = false;
        foreach (var value in expected)
        {
            if (Regex.IsMatch(value, @"\bsession\s*0\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout))
            {
                recognized = true;
                matched |= sessionId == 0;
            }
            else if (value.Contains("interactive", StringComparison.OrdinalIgnoreCase))
            {
                recognized = true;
                matched |= sessionId > 0;
            }
        }

        if (!recognized)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.Session,
                ApplicationComparisonOperator.SessionContext,
                ApplicationComparisonImportance.Medium,
                FormatExpected(expected),
                actual,
                "The profile session text has no supported deterministic session rule.");
        }

        return Result(
            ApplicationComparisonPropertyKind.Session,
            ApplicationComparisonOperator.SessionContext,
            ApplicationComparisonImportance.Medium,
            FormatExpected(expected),
            actual,
            matched,
            matched
                ? "The numeric Windows session is consistent with the expected session context."
                : "The numeric Windows session differs from the expected session context.");
    }

    private static ApplicationComparisonRow CompareCommandLine(
        ApplicationMetadataRecord metadata,
        ApplicationProfileDefinition? catalogProfile,
        ApplicationObservedValue actual,
        string expectedSource)
    {
        var narrative = !string.IsNullOrWhiteSpace(metadata.CommandLineExpectations)
            ? metadata.CommandLineExpectations
            : FormatExpected(catalogProfile?.ObservableExpectations.CommandLine ?? []);
        var rules = catalogProfile?.ObservableExpectations.CommandLineRules ?? [];
        if (string.IsNullOrWhiteSpace(narrative) && rules.Count == 0)
        {
            return NotApplicable(
                ApplicationComparisonPropertyKind.CommandLine,
                ApplicationComparisonOperator.CommandLineMarkers,
                ApplicationComparisonImportance.High,
                "No command-line expectation is defined.",
                actual,
                expectedSource);
        }

        var expected = rules.Count == 0
            ? narrative
            : string.Join(Environment.NewLine, rules.Select(rule =>
                $"{rule.Kind}: {string.Join(", ", rule.Markers)} ({rule.Rationale})"));
        if (!actual.IsAvailable)
        {
            return Unknown(
                ApplicationComparisonPropertyKind.CommandLine,
                ApplicationComparisonOperator.CommandLineMarkers,
                ApplicationComparisonImportance.High,
                expected,
                actual,
                "The command line is unavailable or access was denied; absence is not a mismatch.");
        }

        if (rules.Count == 0)
        {
            return new ApplicationComparisonRow
            {
                PropertyKind = ApplicationComparisonPropertyKind.CommandLine,
                Operator = ApplicationComparisonOperator.CommandLineMarkers,
                Importance = ApplicationComparisonImportance.High,
                Result = ApplicationComparisonResult.NotApplicable,
                ExpectedValue = expected,
                ActualValue = actual.Value,
                Rationale = "The profile contains narrative command-line guidance but no typed marker rule, so it is displayed without inventing a deterministic verdict.",
                EvidenceSource = actual.Source,
                SourceAvailability = actual.Availability
            };
        }

        var failures = new List<string>();
        foreach (var rule in rules)
        {
            var present = rule.Markers
                .Where(marker => !string.IsNullOrWhiteSpace(marker))
                .Select(marker => actual.Value.Contains(marker, StringComparison.OrdinalIgnoreCase))
                .ToList();
            var ruleMatched = rule.Kind switch
            {
                ApplicationCommandLineRuleKind.RequiredAllMarkers => present.Count > 0 && present.All(value => value),
                ApplicationCommandLineRuleKind.RequiredAnyMarker => present.Any(value => value),
                ApplicationCommandLineRuleKind.ForbiddenMarkers => present.All(value => !value),
                _ => false
            };
            if (!ruleMatched)
            {
                failures.Add(rule.Rationale);
            }
        }

        var matched = failures.Count == 0;
        return Result(
            ApplicationComparisonPropertyKind.CommandLine,
            ApplicationComparisonOperator.CommandLineMarkers,
            ApplicationComparisonImportance.High,
            expected,
            actual,
            matched,
            matched
                ? "All typed required/forbidden command-line marker rules are satisfied."
                : $"Typed command-line marker rules were not satisfied: {string.Join("; ", failures)}");
    }

    private static ApplicationComparisonRow CompareSignerPublisher(
        ApplicationMetadataRecord metadata,
        ApplicationProfileDefinition? catalogProfile,
        ApplicationObservedValue actual,
        AuthenticodeSignatureKind signatureKind,
        AuthenticodeVerificationStatus verificationStatus,
        string expectedSource)
    {
        var expected = (catalogProfile?.Discriminators.Companies ?? [])
            .Concat(catalogProfile?.Sources.Select(source => source.Publisher) ?? [])
            .Append(metadata.CompanyVendor)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var expectedDisplay = expected.Count == 0 ? "Expected publisher not specified" : FormatExpected(expected);
        var evidenceSource = string.IsNullOrWhiteSpace(actual.Source) ? expectedSource : actual.Source;
        if (expected.Count == 0)
        {
            return SignerResult(
                ApplicationComparisonResult.Unknown,
                expectedDisplay,
                actual,
                evidenceSource,
                "The application profile does not specify an expected publisher, so signer conformity is Unknown. Signature validity identifies a publisher but does not establish benignness.");
        }

        if (verificationStatus == AuthenticodeVerificationStatus.Unsigned)
        {
            return SignerResult(
                ApplicationComparisonResult.Mismatch,
                expectedDisplay,
                actual,
                evidenceSource,
                $"The process image is explicitly unsigned, but the profile expects one of {expectedDisplay}.");
        }

        if (verificationStatus is AuthenticodeVerificationStatus.Invalid or
            AuthenticodeVerificationStatus.Untrusted or
            AuthenticodeVerificationStatus.Expired or
            AuthenticodeVerificationStatus.Revoked)
        {
            return SignerResult(
                ApplicationComparisonResult.Mismatch,
                expectedDisplay,
                actual,
                evidenceSource,
                $"The {signatureKind} signature status is {verificationStatus}; the expected publisher cannot be established under the recorded verification policy.");
        }

        if (verificationStatus != AuthenticodeVerificationStatus.Valid || !actual.IsAvailable)
        {
            return SignerResult(
                ApplicationComparisonResult.Unknown,
                expectedDisplay,
                actual,
                evidenceSource,
                $"Publisher conformity is Unknown because Authenticode verification status is {verificationStatus} and no policy-valid publisher identity is available. {actual.Availability}".Trim());
        }

        var normalizedActual = NormalizeExact(actual.Value);
        var matchedExpected = expected.FirstOrDefault(value =>
            string.Equals(NormalizeExact(value), normalizedActual, StringComparison.OrdinalIgnoreCase));
        var matched = matchedExpected != null;
        return SignerResult(
            matched ? ApplicationComparisonResult.Match : ApplicationComparisonResult.Mismatch,
            expectedDisplay,
            actual,
            evidenceSource,
            matched
                ? $"The policy-valid {signatureKind} publisher exactly matches expected value '{matchedExpected}'. Signature validity identifies the publisher but does not establish benignness."
                : $"The policy-valid {signatureKind} publisher '{actual.Value}' does not exactly match any expected publisher value. Signature validity identifies the publisher but does not establish benignness.");
    }

    private static ApplicationComparisonRow SignerResult(
        ApplicationComparisonResult result,
        string expected,
        ApplicationObservedValue actual,
        string evidenceSource,
        string rationale) => new()
    {
        PropertyKind = ApplicationComparisonPropertyKind.SignerPublisher,
        Operator = ApplicationComparisonOperator.ExactValueAny,
        Importance = ApplicationComparisonImportance.Critical,
        Result = result,
        ExpectedValue = expected,
        ActualValue = actual.IsAvailable ? actual.Value : "<not available>",
        Rationale = rationale,
        EvidenceSource = evidenceSource,
        SourceAvailability = actual.Availability
    };

    private static string NormalizeExact(string value)
        => string.Join(' ', (value ?? string.Empty).Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static ApplicationComparisonRow Result(
        ApplicationComparisonPropertyKind kind,
        ApplicationComparisonOperator comparisonOperator,
        ApplicationComparisonImportance importance,
        string expected,
        ApplicationObservedValue actual,
        bool matched,
        string rationale)
        => new()
        {
            PropertyKind = kind,
            Operator = comparisonOperator,
            Importance = importance,
            Result = matched ? ApplicationComparisonResult.Match : ApplicationComparisonResult.Mismatch,
            ExpectedValue = expected,
            ActualValue = actual.Value,
            Rationale = rationale,
            EvidenceSource = actual.Source,
            SourceAvailability = actual.Availability
        };

    private static ApplicationComparisonRow Unknown(
        ApplicationComparisonPropertyKind kind,
        ApplicationComparisonOperator comparisonOperator,
        ApplicationComparisonImportance importance,
        string expected,
        ApplicationObservedValue actual,
        string rationale)
        => new()
        {
            PropertyKind = kind,
            Operator = comparisonOperator,
            Importance = importance,
            Result = ApplicationComparisonResult.Unknown,
            ExpectedValue = expected,
            ActualValue = actual.IsAvailable ? actual.Value : "<not available>",
            Rationale = rationale,
            EvidenceSource = actual.Source,
            SourceAvailability = actual.Availability
        };

    private static ApplicationComparisonRow NotApplicable(
        ApplicationComparisonPropertyKind kind,
        ApplicationComparisonOperator comparisonOperator,
        ApplicationComparisonImportance importance,
        string rationale,
        ApplicationObservedValue actual,
        string expectedSource)
        => new()
        {
            PropertyKind = kind,
            Operator = comparisonOperator,
            Importance = importance,
            Result = ApplicationComparisonResult.NotApplicable,
            ExpectedValue = "<not specified>",
            ActualValue = actual.IsAvailable ? actual.Value : "<not available>",
            Rationale = rationale,
            EvidenceSource = actual.IsAvailable ? actual.Source : expectedSource,
            SourceAvailability = actual.Availability
        };

    private static IReadOnlyList<string> ResolveValues(
        ApplicationMetadataRecord metadata,
        string metadataValue,
        IReadOnlyList<string>? catalogValues)
    {
        if (metadata.RecordOrigin != ApplicationProfileOrigin.BuiltInCatalog && !string.IsNullOrWhiteSpace(metadataValue))
        {
            return [metadataValue.Trim()];
        }

        return catalogValues?.Where(value => !string.IsNullOrWhiteSpace(value)).ToList()
            ?? (string.IsNullOrWhiteSpace(metadataValue) ? [] : [metadataValue.Trim()]);
    }

    private static bool PathMatches(string actual, string pattern)
    {
        var normalizedActual = NormalizePath(actual);
        var normalizedPattern = NormalizePath(pattern);
        if (!normalizedPattern.Contains('*') && !normalizedPattern.Contains('?'))
        {
            return normalizedActual.Contains(normalizedPattern, StringComparison.Ordinal);
        }

        var expression = "^" + Regex.Escape(normalizedPattern)
            .Replace("\\*", ".*", StringComparison.Ordinal)
            .Replace("\\?", ".", StringComparison.Ordinal) + "$";
        return Regex.IsMatch(
            normalizedActual,
            expression,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            RegexTimeout);
    }

    private static string NormalizePath(string value)
        => value.Trim().Replace('/', '\\').ToLowerInvariant();

    private static string NormalizeValue(string value)
        => string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToLowerInvariant();

    private static string NormalizeComparableExecutableFilename(string value)
    {
        var normalized = ApplicationPatternValidator.NormalizeFilename(value);
        return normalized.Length > ".exe".Length && normalized.EndsWith(".exe", StringComparison.Ordinal)
            ? normalized[..^".exe".Length]
            : normalized;
    }

    private static string NormalizeAccount(string value)
    {
        var normalized = NormalizeValue(value).Replace(" ", string.Empty, StringComparison.Ordinal);
        var slash = normalized.LastIndexOf('\\');
        return slash >= 0 ? normalized[(slash + 1)..] : normalized;
    }

    private static string MapExpectedAccount(string value)
    {
        var normalized = NormalizeAccount(value);
        if (normalized.Contains("localsystem", StringComparison.Ordinal))
        {
            return "system";
        }

        if (normalized.Contains("localservice", StringComparison.Ordinal))
        {
            return "localservice";
        }

        if (normalized.Contains("networkservice", StringComparison.Ordinal))
        {
            return "networkservice";
        }

        return string.Empty;
    }

    private static string FormatExpected(IEnumerable<string> values)
        => string.Join(Environment.NewLine, values.Where(value => !string.IsNullOrWhiteSpace(value)));

    private static string FormatCandidates(
        IReadOnlyList<ApplicationCatalogMatch> candidates,
        string? selectedProfileId)
    {
        if (candidates.Count == 0)
        {
            return "No normalized-filename catalog candidates.";
        }

        const int maximumCandidates = 8;
        var lines = candidates.Take(maximumCandidates).Select(candidate =>
        {
            var selected = string.Equals(candidate.Profile.ProfileId, selectedProfileId, StringComparison.Ordinal)
                ? "Selected"
                : "Candidate";
            return $"{selected}: {candidate.Profile.DisplayName} [{candidate.Profile.ProfileId}] - {candidate.SelectionReason}";
        }).ToList();
        if (candidates.Count > maximumCandidates)
        {
            lines.Add($"{candidates.Count - maximumCandidates} additional candidates omitted from the bounded display.");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
