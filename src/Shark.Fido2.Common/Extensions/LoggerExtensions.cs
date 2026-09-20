using Microsoft.Extensions.Logging;

namespace Shark.Fido2.Common.Extensions;

public static class LoggerExtensions
{
    public static void LogDebugIfEnabled(this ILogger logger, string? message, params object?[] args)
    {
        if (logger.IsEnabled(LogLevel.Debug))
        {
            logger.LogDebug(message, args);
        }
    }
}
