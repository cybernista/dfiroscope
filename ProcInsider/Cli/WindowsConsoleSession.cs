using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcInsider.Cli;

internal enum WindowsConsoleConnectionOutcome
{
    PreservedInheritedHandles = 0,
    AttachedToParent = 1,
    AlreadyAttached = 2,
    Allocated = 3,
    Unavailable = 4
}

internal sealed record WindowsConsoleConnectionResult(
    WindowsConsoleConnectionOutcome Outcome,
    bool InputAvailable,
    bool OutputAvailable,
    bool ErrorAvailable);

internal interface IWindowsConsoleNative
{
    IntPtr GetStandardHandle(int kind);

    bool AttachParentConsole();

    bool AllocateConsole();

    int GetLastError();
}

internal sealed class SystemWindowsConsoleNative : IWindowsConsoleNative
{
    private const uint AttachParentProcess = 0xFFFFFFFF;

    public IntPtr GetStandardHandle(int kind) => GetStdHandle(kind);

    public bool AttachParentConsole() => AttachConsole(AttachParentProcess);

    public bool AllocateConsole() => AllocConsole();

    public int GetLastError() => Marshal.GetLastPInvokeError();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();
}

internal static class WindowsConsoleSession
{
    internal const int StandardInputHandle = -10;
    internal const int StandardOutputHandle = -11;
    internal const int StandardErrorHandle = -12;
    internal const int ErrorAccessDenied = 5;

    public static WindowsConsoleConnectionResult EnsureForCommandLine() =>
        Connect(new SystemWindowsConsoleNative(), rebindManagedStreams: true);

    internal static WindowsConsoleConnectionResult Connect(
        IWindowsConsoleNative native,
        bool rebindManagedStreams)
    {
        ArgumentNullException.ThrowIfNull(native);
        var inputAvailable = IsUsable(native.GetStandardHandle(StandardInputHandle));
        var outputAvailable = IsUsable(native.GetStandardHandle(StandardOutputHandle));
        var errorAvailable = IsUsable(native.GetStandardHandle(StandardErrorHandle));

        WindowsConsoleConnectionOutcome outcome;
        if (inputAvailable || outputAvailable || errorAvailable)
        {
            // A process runner may provide only a subset of redirected handles. Do not
            // attach or allocate in that case because Windows can replace those handles.
            outcome = WindowsConsoleConnectionOutcome.PreservedInheritedHandles;
        }
        else if (native.AttachParentConsole())
        {
            outcome = WindowsConsoleConnectionOutcome.AttachedToParent;
        }
        else if (native.GetLastError() == ErrorAccessDenied)
        {
            // ERROR_ACCESS_DENIED means this process already has a console. Its managed
            // streams may simply have been initialized before the WinExe attached.
            outcome = WindowsConsoleConnectionOutcome.AlreadyAttached;
        }
        else
        {
            outcome = native.AllocateConsole()
                ? WindowsConsoleConnectionOutcome.Allocated
                : WindowsConsoleConnectionOutcome.Unavailable;
        }

        inputAvailable = IsUsable(native.GetStandardHandle(StandardInputHandle));
        outputAvailable = IsUsable(native.GetStandardHandle(StandardOutputHandle));
        errorAvailable = IsUsable(native.GetStandardHandle(StandardErrorHandle));
        if (rebindManagedStreams)
        {
            RebindManagedStreams(inputAvailable, outputAvailable, errorAvailable);
        }

        return new WindowsConsoleConnectionResult(
            outcome,
            inputAvailable,
            outputAvailable,
            errorAvailable);
    }

    private static bool IsUsable(IntPtr handle) =>
        handle != IntPtr.Zero && handle != new IntPtr(-1);

    private static void RebindManagedStreams(
        bool inputAvailable,
        bool outputAvailable,
        bool errorAvailable)
    {
        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        if (inputAvailable)
        {
            Try(() => Console.SetIn(new StreamReader(
                Console.OpenStandardInput(),
                utf8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 4096,
                leaveOpen: false)));
        }

        if (outputAvailable)
        {
            Try(() => Console.SetOut(new StreamWriter(
                Console.OpenStandardOutput(),
                utf8,
                bufferSize: 4096,
                leaveOpen: false)
            {
                AutoFlush = true
            }));
        }

        if (errorAvailable)
        {
            Try(() => Console.SetError(new StreamWriter(
                Console.OpenStandardError(),
                utf8,
                bufferSize: 4096,
                leaveOpen: false)
            {
                AutoFlush = true
            }));
        }
    }

    private static void Try(Action action)
    {
        try
        {
            action();
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }
}
