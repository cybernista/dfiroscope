using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class AdvancedSearchParser
{
    private static readonly HashSet<string> SupportedFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "kind",
        "type",
        "status",
        "state",
        "source",
        "process",
        "processname",
        "name",
        "pid",
        "path",
        "commandline",
        "cmd",
        "user",
        "company",
        "description",
        "hash",
        "sha256",
        "parent",
        "target",
        "summary",
        "details",
        "risk",
        "eventcode",
        "action",
        "category",
        "processguid",
        "guid",
        "module",
        "version",
        "baseaddress",
        "objecttype",
        "objectname",
        "access",
        "handle"
    };

    private readonly List<Token> _tokens;
    private readonly List<AdvancedSearchDiagnostic> _diagnostics = new();
    private int _position;

    private AdvancedSearchParser(List<Token> tokens, IReadOnlyList<AdvancedSearchDiagnostic> lexDiagnostics)
    {
        _tokens = tokens;
        _diagnostics.AddRange(lexDiagnostics);
    }

    public static AdvancedSearchParseResult Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return new AdvancedSearchParseResult
            {
                Diagnostics = new[]
                {
                    new AdvancedSearchDiagnostic
                    {
                        Message = "Search query cannot be empty.",
                        Position = 0
                    }
                }
            };
        }

        var tokens = Tokenize(text, out var lexDiagnostics);
        var parser = new AdvancedSearchParser(tokens, lexDiagnostics);
        var expression = parser.ParseOr();

        if (!parser.IsAtEnd)
        {
            parser.AddDiagnostic($"Unexpected token '{parser.Peek().Text}'.", parser.Peek().Position);
            expression = null;
        }

        if (parser._diagnostics.Count > 0)
        {
            expression = null;
        }

        return new AdvancedSearchParseResult
        {
            Expression = expression,
            Diagnostics = parser._diagnostics
        };
    }

    private AdvancedSearchExpression? ParseOr()
    {
        var expression = ParseAnd();
        while (Match(TokenKind.Or))
        {
            var operatorToken = Previous();
            var right = ParseAnd();
            if (expression == null || right == null)
            {
                AddDiagnostic("OR must have search terms on both sides.", operatorToken.Position);
                return null;
            }

            expression = AdvancedSearchExpression.Binary(AdvancedSearchExpressionKind.Or, expression, right);
        }

        return expression;
    }

    private AdvancedSearchExpression? ParseAnd()
    {
        var expression = ParseUnary();
        while (Match(TokenKind.And) || StartsImplicitAnd())
        {
            var operatorPosition = PreviousOrCurrentPosition();
            var right = ParseUnary();
            if (expression == null || right == null)
            {
                AddDiagnostic("AND must have search terms on both sides.", operatorPosition);
                return null;
            }

            expression = AdvancedSearchExpression.Binary(AdvancedSearchExpressionKind.And, expression, right);
        }

        return expression;
    }

    private AdvancedSearchExpression? ParseUnary()
    {
        if (!Match(TokenKind.Not))
        {
            return ParsePrimary();
        }

        var notToken = Previous();
        var child = ParseUnary();
        if (child == null)
        {
            AddDiagnostic("NOT must be followed by a search term or group.", notToken.Position);
            return null;
        }

        return AdvancedSearchExpression.Unary(AdvancedSearchExpressionKind.Not, child);
    }

    private AdvancedSearchExpression? ParsePrimary()
    {
        if (Match(TokenKind.LeftParen))
        {
            var open = Previous();
            var expression = ParseOr();
            if (!Match(TokenKind.RightParen))
            {
                AddDiagnostic("Missing closing parenthesis.", open.Position);
                return null;
            }

            return expression;
        }

        if (Match(TokenKind.Word, TokenKind.QuotedText))
        {
            var token = Previous();
            if (token.Kind == TokenKind.Word &&
                Check(TokenKind.Colon) &&
                SupportedFields.Contains(token.Text))
            {
                Advance();
                if (!Match(TokenKind.Word, TokenKind.QuotedText))
                {
                    AddDiagnostic($"Field '{token.Text}' must have a value after ':'.", token.Position);
                    return null;
                }

                var value = Previous();
                return AdvancedSearchExpression.Term(value.Text, token.Text, value.Kind == TokenKind.QuotedText);
            }

            if (token.Kind == TokenKind.Word &&
                Check(TokenKind.Colon) &&
                !SupportedFields.Contains(token.Text))
            {
                Advance();
                if (Match(TokenKind.Word, TokenKind.QuotedText))
                {
                    AddDiagnostic($"Unsupported search field '{token.Text}'.", token.Position);
                    return null;
                }

                AddDiagnostic($"Unsupported search field '{token.Text}'.", token.Position);
                return null;
            }

            return AdvancedSearchExpression.Term(token.Text, isQuoted: token.Kind == TokenKind.QuotedText);
        }

        if (Match(TokenKind.RightParen))
        {
            AddDiagnostic("Unexpected closing parenthesis.", Previous().Position);
            return null;
        }

        if (IsAtEnd)
        {
            AddDiagnostic("Search query ended before a term was provided.", PreviousOrCurrentPosition());
            return null;
        }

        AddDiagnostic($"Expected a search term, quoted string, NOT, or group before '{Peek().Text}'.", Peek().Position);
        return null;
    }

    private bool StartsImplicitAnd()
    {
        return Check(TokenKind.Word) ||
               Check(TokenKind.QuotedText) ||
               Check(TokenKind.Not) ||
               Check(TokenKind.LeftParen);
    }

    private bool Match(params TokenKind[] kinds)
    {
        foreach (var kind in kinds)
        {
            if (Check(kind))
            {
                Advance();
                return true;
            }
        }

        return false;
    }

    private bool Check(TokenKind kind)
    {
        return !IsAtEnd && Peek().Kind == kind;
    }

    private Token Advance()
    {
        if (!IsAtEnd)
        {
            _position++;
        }

        return Previous();
    }

    private bool IsAtEnd => Peek().Kind == TokenKind.End;

    private Token Peek()
    {
        return _tokens[_position];
    }

    private Token Previous()
    {
        return _tokens[Math.Max(0, _position - 1)];
    }

    private int PreviousOrCurrentPosition()
    {
        return _position > 0 ? Previous().Position : Peek().Position;
    }

    private void AddDiagnostic(string message, int position)
    {
        _diagnostics.Add(new AdvancedSearchDiagnostic
        {
            Message = message,
            Position = position
        });
    }

    private static List<Token> Tokenize(string text, out IReadOnlyList<AdvancedSearchDiagnostic> diagnostics)
    {
        var tokens = new List<Token>();
        var errors = new List<AdvancedSearchDiagnostic>();
        var index = 0;

        while (index < text.Length)
        {
            var current = text[index];
            if (char.IsWhiteSpace(current))
            {
                index++;
                continue;
            }

            if (current == '(')
            {
                tokens.Add(new Token(TokenKind.LeftParen, "(", index));
                index++;
                continue;
            }

            if (current == ')')
            {
                tokens.Add(new Token(TokenKind.RightParen, ")", index));
                index++;
                continue;
            }

            if (current == ':')
            {
                tokens.Add(new Token(TokenKind.Colon, ":", index));
                index++;
                continue;
            }

            if (current == '"')
            {
                tokens.Add(ReadQuotedText(text, index, errors, out index));
                continue;
            }

            tokens.Add(ReadWord(text, index, out index));
        }

        tokens.Add(new Token(TokenKind.End, string.Empty, text.Length));
        diagnostics = errors;
        return tokens;
    }

    private static Token ReadQuotedText(
        string text,
        int start,
        List<AdvancedSearchDiagnostic> diagnostics,
        out int nextIndex)
    {
        var value = new List<char>();
        var index = start + 1;
        while (index < text.Length)
        {
            var current = text[index];
            if (current == '"')
            {
                nextIndex = index + 1;
                return new Token(TokenKind.QuotedText, new string(value.ToArray()), start);
            }

            if (current == '\\' && index + 1 < text.Length && text[index + 1] == '"')
            {
                value.Add('"');
                index += 2;
                continue;
            }

            value.Add(current);
            index++;
        }

        diagnostics.Add(new AdvancedSearchDiagnostic
        {
            Message = "Missing closing quote.",
            Position = start
        });
        nextIndex = text.Length;
        return new Token(TokenKind.QuotedText, new string(value.ToArray()), start);
    }

    private static Token ReadWord(string text, int start, out int nextIndex)
    {
        var index = start;
        while (index < text.Length &&
               !char.IsWhiteSpace(text[index]) &&
               text[index] != '(' &&
               text[index] != ')' &&
               text[index] != ':' &&
               text[index] != '"')
        {
            index++;
        }

        var value = text[start..index];
        var kind = value.ToUpperInvariant() switch
        {
            "AND" => TokenKind.And,
            "OR" => TokenKind.Or,
            "NOT" => TokenKind.Not,
            _ => TokenKind.Word
        };

        nextIndex = index;
        return new Token(kind, value, start);
    }

    private enum TokenKind
    {
        Word,
        QuotedText,
        And,
        Or,
        Not,
        LeftParen,
        RightParen,
        Colon,
        End
    }

    private readonly record struct Token(TokenKind Kind, string Text, int Position);
}
