using System.Runtime.InteropServices;
using System.Text;

namespace ProcInsider.Services.Ai;

internal static class DpapiProtector
{
    private const int CryptProtectUiForbidden = 0x1;

    public static string ProtectToBase64(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return string.Empty;
        }

        var protectedBytes = Protect(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(protectedBytes);
    }

    public static string UnprotectFromBase64(string protectedSecret)
    {
        if (string.IsNullOrWhiteSpace(protectedSecret))
        {
            return string.Empty;
        }

        var bytes = Convert.FromBase64String(protectedSecret);
        return Encoding.UTF8.GetString(Unprotect(bytes));
    }

    private static byte[] Protect(byte[] bytes)
    {
        return RunDpapi(bytes, protect: true);
    }

    private static byte[] Unprotect(byte[] bytes)
    {
        return RunDpapi(bytes, protect: false);
    }

    private static byte[] RunDpapi(byte[] bytes, bool protect)
    {
        var input = default(DataBlob);
        var output = default(DataBlob);
        try
        {
            input.cbData = bytes.Length;
            input.pbData = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, input.pbData, bytes.Length);

            var ok = protect
                ? CryptProtectData(ref input, "DFIRoscope Live AI secret", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, ref output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, ref output);
            if (!ok)
            {
                throw new InvalidOperationException($"Windows DPAPI failed with error {Marshal.GetLastWin32Error()}.");
            }

            var result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, output.cbData);
            return result;
        }
        finally
        {
            if (input.pbData != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(input.pbData);
            }

            if (output.pbData != IntPtr.Zero)
            {
                LocalFree(output.pbData);
            }
        }
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn,
        string? szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn,
        IntPtr ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DataBlob pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }
}
