using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;

namespace Shark.Fido2.Common.Extensions;

[SuppressMessage("Usage", "CA2254:Template should be a static expression", Justification = "Message is forwarded from caller in a generic logging wrapper.")]
public static class LoggerExtensions
{
    public static void LogInformationIfEnabled(this ILogger logger, string? message, params object?[] args)
    {
        if (logger.IsEnabled(LogLevel.Information))
        {
            var sanitizedArgs = args.Select(a => a is string s ? SanitizeForLog(s) : a).ToArray();
            logger.LogInformation(message, sanitizedArgs);
        }
    }

    public static void LogDebugIfEnabled(this ILogger logger, string? message, params object?[] args)
    {
        if (logger.IsEnabled(LogLevel.Debug))
        {
            var sanitizedArgs = args.Select(a => a is string s ? SanitizeForLog(s) : a).ToArray();
            logger.LogDebug(message, sanitizedArgs);
        }
    }

    private static string SanitizeForLog(string value)
    {
        return value
            .Replace("\r\n", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal);
    }
}
