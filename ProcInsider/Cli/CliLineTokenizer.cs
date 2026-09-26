using System.Text;

namespace ProcInsider.Cli;

internal sealed record CliLineTokenizationResult(
    IReadOnlyList<string> Tokens,
    string ErrorCode,
    string ErrorMessage)
{
    public bool Success => string.IsNullOrEmpty(ErrorCode);
}

internal static class CliLineTokenizer
{
    public const int MaxLineLength = 32_768;
    public const int MaxTokenLength = 4_096;
    public const int MaxTokenCount = 128;
    public const string ErrorCode = "InvalidShellInput";

    public static CliLineTokenizationResult Tokenize(string? line)
    {
        if (line == null)
        {
            return Succeeded([]);
        }

        if (line.Length > MaxLineLength)
        {
            return Failed($"A shell line may contain at most {MaxLineLength} characters.");
        }

        var tokens = new List<string>();
        var current = new StringBuilder();
        var tokenStarted = false;
        char? quote = null;

        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (quote.HasValue)
            {
                if (character == quote.Value)
                {
                    if (index + 1 < line.Length && line[index + 1] == quote.Value)
                    {
                        current.Append(character);
                        index++;
                    }
                    else
                    {
                        quote = null;
                    }
                }
                else
                {
                    current.Append(character);
                }

                if (current.Length > MaxTokenLength)
                {
                    return Failed($"A shell argument may contain at most {MaxTokenLength} characters.");
                }

                continue;
            }

            if (character is '\'' or '"')
            {
                quote = character;
                tokenStarted = true;
                continue;
            }

            if (char.IsWhiteSpace(character))
            {
                if (tokenStarted)
                {
                    if (!TryAddToken(tokens, current.ToString(), out var failure))
                    {
                        return failure!;
                    }

                    current.Clear();
                    tokenStarted = false;
                }

                continue;
            }

            current.Append(character);
            tokenStarted = true;
            if (current.Length > MaxTokenLength)
            {
                return Failed($"A shell argument may contain at most {MaxTokenLength} characters.");
            }
        }

        if (quote.HasValue)
        {
            return Failed($"The shell line has an incomplete {quote.Value} quote.");
        }

        if (tokenStarted && !TryAddToken(tokens, current.ToString(), out var finalFailure))
        {
            return finalFailure!;
        }

        return Succeeded(tokens);
    }

    private static bool TryAddToken(
        ICollection<string> tokens,
        string token,
        out CliLineTokenizationResult? failure)
    {
        if (tokens.Count >= MaxTokenCount)
        {
            failure = Failed($"A shell line may contain at most {MaxTokenCount} arguments.");
            return false;
        }

        tokens.Add(token);
        failure = null;
        return true;
    }

    private static CliLineTokenizationResult Succeeded(IReadOnlyList<string> tokens) =>
        new(tokens, string.Empty, string.Empty);

    private static CliLineTokenizationResult Failed(string message) =>
        new([], ErrorCode, CliValueSanitizer.OneLine(message));
}
