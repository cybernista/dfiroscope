using System.Text;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal static class AgentLog
{
    public static TextWriter Open(string? logPath = null)
    {
        logPath ??= Path.Combine(
            ProcInsider.Services.SessionPathService.CreateDefaultSession().LogsDirectory,
            AgentRuntimeIdentity.LogFileName);

        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? AppContext.BaseDirectory);

        var fileWriter = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = true
        };

        return TextWriter.Synchronized(new TeeTextWriter(Console.Out, fileWriter));
    }

    private sealed class TeeTextWriter : TextWriter
    {
        private readonly TextWriter _first;
        private readonly TextWriter _second;

        public TeeTextWriter(TextWriter first, TextWriter second)
        {
            _first = first;
            _second = second;
        }

        public override Encoding Encoding => _first.Encoding;

        public override void WriteLine(string? value)
        {
            _first.WriteLine(value);
            _second.WriteLine(value);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _second.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
