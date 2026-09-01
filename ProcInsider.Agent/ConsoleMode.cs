using System.Runtime.InteropServices;

namespace ProcInsider.Agent;

internal static class ConsoleMode
{
    private const uint AttachParentProcess = 0xFFFFFFFF;

    public static void EnableIfRequested(bool foreground)
    {
        if (!foreground)
        {
            return;
        }

        if (!AttachConsole(AttachParentProcess))
        {
            AllocConsole();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();
}
