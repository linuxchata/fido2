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
        textWriter.Write($" {logEntry.LogLevel} ");

        WriteScopeInformation(scopeProvider, textWriter);

        var className = logEntry.Category?[(logEntry.Category.LastIndexOf('.') + 1)..] ?? logEntry.Category;
        var message = logEntry.Formatter?.Invoke(logEntry.State, logEntry.Exception);
        textWriter.Write($"[{className}] {message}");

        textWriter.Write(Environment.NewLine);
    }

    private static void WriteScopeInformation(IExternalScopeProvider? scopeProvider, TextWriter textWriter)
    {
        scopeProvider?.ForEachScope(
            (scope, state) =>
            {
                if (scope is IReadOnlyList<KeyValuePair<string, object>> kvps)
                {
                    foreach (var kv in kvps)
                    {
                        if (kv.Key == "TraceId")
                        {
                            state.Write(scope);
                            state.Write(' ');
                        }
                    }
                }
            }, textWriter);
    }
}
