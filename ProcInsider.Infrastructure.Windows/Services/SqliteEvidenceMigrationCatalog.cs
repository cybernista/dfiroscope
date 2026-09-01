using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed record SqliteEvidenceMigrationStep(
    CaptureMigrationDefinition Definition,
    Action<SqliteEvidenceMigrationExecutionContext> Execute);

internal sealed class SqliteEvidenceMigrationExecutionContext
{
    private readonly SqliteStagingStore _store;

    public SqliteEvidenceMigrationExecutionContext(
        SqliteStagingStore store,
        CancellationToken cancellationToken)
    {
        _store = store;
        CancellationToken = cancellationToken;
    }

    public CancellationToken CancellationToken { get; }

    public void Apply(string migrationId)
    {
        CancellationToken.ThrowIfCancellationRequested();
        _store.ApplyCatalogMigration(migrationId, CancellationToken);
        CancellationToken.ThrowIfCancellationRequested();
    }
}

/// <summary>
/// Viewer-owned SQLite execution binding for the immutable Core migration metadata catalog.
/// </summary>
public static class SqliteEvidenceMigrationCatalog
{
    public static IReadOnlyList<CaptureMigrationDefinition> Definitions { get; } =
        CaptureCompatibilityPolicy.Migrations;

    private static readonly IReadOnlyList<SqliteEvidenceMigrationStep> MigrationSteps = BuildSteps();

    internal static IReadOnlyList<SqliteEvidenceMigrationStep> Steps => MigrationSteps;

    internal static SqliteEvidenceMigrationStep GetStep(string migrationId)
        => MigrationSteps.FirstOrDefault(
               step => string.Equals(step.Definition.MigrationId, migrationId, StringComparison.Ordinal))
           ?? throw new ArgumentOutOfRangeException(nameof(migrationId), migrationId, "Unknown SQLite evidence migration ID.");

    public static void ValidateDefinitions(IReadOnlyList<CaptureMigrationDefinition> definitions)
        => CaptureCompatibilityPolicy.ValidateMigrationDefinitions(definitions);

    private static IReadOnlyList<SqliteEvidenceMigrationStep> BuildSteps()
    {
        ValidateDefinitions(Definitions);
        return Definitions
            .Select(definition => new SqliteEvidenceMigrationStep(
                definition,
                context => context.Apply(definition.MigrationId)))
            .ToArray();
    }
}
