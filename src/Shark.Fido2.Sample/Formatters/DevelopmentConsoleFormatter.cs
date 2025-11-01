using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace Shark.Fido2.Sample.Formatters;

public class DevelopmentConsoleFormatter : ConsoleFormatter
{
    public const string FormatterName = "development";

    public DevelopmentConsoleFormatter()
        : base(FormatterName)
    {
    }

    public override void Write<TState>(
        in LogEntry<TState> logEntry,
        IExternalScopeProvider? scopeProvider,
        TextWriter textWriter)
    {
        var timestamp = DateTime.UtcNow.ToString("O");
        textWriter.Write($"{timestamp} {logEntry.LogLevel} ");

        var className = logEntry.Category?[(logEntry.Category.LastIndexOf('.') + 1)..] ?? logEntry.Category;
        var message = logEntry.Formatter?.Invoke(logEntry.State, logEntry.Exception);
        textWriter.Write($"[{className}] {message}");

        textWriter.Write(Environment.NewLine);
    }
}
