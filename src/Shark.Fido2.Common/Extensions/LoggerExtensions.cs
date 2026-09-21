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
            var sanitizedArgs = args.Select(SanitizeArgumentForLog).ToArray();
            logger.LogInformation(message, sanitizedArgs);
        }
    }

    public static void LogDebugIfEnabled(this ILogger logger, string? message, params object?[] args)
    {
        if (logger.IsEnabled(LogLevel.Debug))
        {
            var sanitizedArgs = args.Select(SanitizeArgumentForLog).ToArray();
            logger.LogDebug(message, sanitizedArgs);
        }
    }

    private static object? SanitizeArgumentForLog(object? value)
    {
        if (value == null)
        {
            return null;
        }

        if (value is string stringValue)
        {
            return SanitizeForLog(stringValue);
        }

        var text = value is IFormattable formattable
            ? formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture)
            : value.ToString();

        return SanitizeForLog(text ?? string.Empty);
    }

    private static string SanitizeForLog(string value)
    {
        // Replace \r\n, \n and \r
        if (value.IndexOfAny(['\r', '\n']) < 0)
        {
            return value;
        }

        return string.Create(value.Length, value, static (span, src) =>
        {
            for (var i = 0; i < src.Length; i++)
            {
                span[i] = src[i] is '\r' or '\n' ? ' ' : src[i];
            }
        });
    }
}
