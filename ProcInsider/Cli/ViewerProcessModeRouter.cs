namespace ProcInsider.Cli;

internal enum ViewerProcessMode
{
    Gui = 0,
    CommandLine = 1
}

internal static class ViewerProcessModeRouter
{
    public static ViewerProcessMode Select(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Count == 0
            ? ViewerProcessMode.Gui
            : ViewerProcessMode.CommandLine;
    }
}
