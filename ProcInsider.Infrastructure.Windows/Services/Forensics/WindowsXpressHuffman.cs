using System.Runtime.InteropServices;

namespace ProcInsider.Services.Forensics;

/// <summary>Bounded MAM04 interpretation; cancellation cannot interrupt the synchronous native call.</summary>
internal static class WindowsXpressHuffman
{
    internal const int MaximumDecodedBytes = 16 * 1024 * 1024;
    private const uint MaximumWorkspaceBytes = 4 * 1024 * 1024;

    internal static byte[] Decode(byte[] compressed, uint declaredBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (declaredBytes == 0 || declaredBytes > MaximumDecodedBytes || compressed.Length == 0 || compressed.Length > PrefetchParser.MaximumInputBytes)
            throw new InvalidDataException("Invalid XPRESS-Huffman input or decoded length.");
        var status = RtlGetCompressionWorkSpaceSize(4, out _, out var workspaceBytes);
        if (status != 0 || workspaceBytes == 0 || workspaceBytes > MaximumWorkspaceBytes)
            throw new InvalidDataException("XPRESS-Huffman workspace is unavailable or exceeds its allowance.");
        var workspace = Marshal.AllocHGlobal(checked((int)workspaceBytes));
        try
        {
            var decoded = new byte[checked((int)declaredBytes)];
            cancellationToken.ThrowIfCancellationRequested();
            status = RtlDecompressBufferEx(4, decoded, declaredBytes, compressed, checked((uint)compressed.Length), out var actualBytes, workspace);
            cancellationToken.ThrowIfCancellationRequested();
            if (status != 0 || actualBytes != declaredBytes)
                throw new InvalidDataException("XPRESS-Huffman status or decoded length does not match the wrapper.");
            return decoded;
        }
        finally { Marshal.FreeHGlobal(workspace); }
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int RtlGetCompressionWorkSpaceSize(ushort format, out uint compressBytes, out uint decompressBytes);
    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int RtlDecompressBufferEx(ushort format, [Out] byte[] output, uint outputBytes, byte[] input, uint inputBytes, out uint actualBytes, IntPtr workspace);
}
