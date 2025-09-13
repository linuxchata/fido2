using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace Shark.Fido2.Sample.Formatters;

public class CustomConsoleFormatter : ConsoleFormatter
{
    public const string FormatterName = "custom";

    public CustomConsoleFormatter()
        : base(FormatterName)
    {
    }

    public override void Write<TState>(
        in LogEntry<TState> logEntry,
        IExternalScopeProvider? scopeProvider,
        TextWriter textWriter)
    {
        var timestamp = DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss");
        var message = logEntry.Formatter?.Invoke(logEntry.State, logEntry.Exception);
        textWriter.WriteLine($"{timestamp} {logEntry.LogLevel} [{logEntry.Category}] {message}");
    }
}
