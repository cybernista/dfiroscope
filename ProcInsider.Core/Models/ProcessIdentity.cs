using System;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models;

public enum ProcessAliasKind
{
    Unknown = 0,
    LegacyProcessKey,
    SysmonProcessGuid,
    ProcmonSyntheticKey,
    SourceNativeId
}

public sealed record ProcessAlias
{
    public string ProcessEntityId { get; init; } = string.Empty;
    public ProcessAliasKind Kind { get; init; }
    public string Value { get; init; } = string.Empty;
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
}

public static class ProcessEntityIdentity
{
    public static string CreateExact(
        string caseId,
        string evidenceSessionId,
        string hostId,
        string executionRootId,
        int processId,
        DateTime startTimeUtc)
    {
        var naturalIdentity = string.Join("\u001f",
            caseId ?? string.Empty,
            evidenceSessionId ?? string.Empty,
            hostId ?? string.Empty,
            executionRootId ?? string.Empty,
            processId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            startTimeUtc.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(naturalIdentity));
        Span<byte> guidBytes = stackalloc byte[16];
        bytes.AsSpan(0, 16).CopyTo(guidBytes);
        guidBytes[7] = (byte)((guidBytes[7] & 0x0f) | 0x50);
        guidBytes[8] = (byte)((guidBytes[8] & 0x3f) | 0x80);
        return new Guid(guidBytes).ToString("N");
    }

    public static string CreateOpaque() => Guid.NewGuid().ToString("N");

    public static string CreateScopedAlias(
        string caseId,
        string evidenceSessionId,
        string hostId,
        string executionRootId,
        ProcessAliasKind aliasKind,
        string aliasValue)
        => CreateDeterministic(
            caseId,
            evidenceSessionId,
            hostId,
            executionRootId,
            aliasKind.ToString(),
            aliasValue);

    public static string CreateSourceScoped(string sourceRunId, ProcessAliasKind aliasKind, string aliasValue)
        => CreateDeterministic(sourceRunId, aliasKind.ToString(), aliasValue);

    private static string CreateDeterministic(params string[] components)
    {
        var naturalIdentity = string.Join("\u001f", components.Select(component => component ?? string.Empty));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(naturalIdentity));
        Span<byte> guidBytes = stackalloc byte[16];
        bytes.AsSpan(0, 16).CopyTo(guidBytes);
        guidBytes[7] = (byte)((guidBytes[7] & 0x0f) | 0x50);
        guidBytes[8] = (byte)((guidBytes[8] & 0x3f) | 0x80);
        return new Guid(guidBytes).ToString("N");
    }
}
