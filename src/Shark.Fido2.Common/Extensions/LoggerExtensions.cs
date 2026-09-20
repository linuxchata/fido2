using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;

namespace Shark.Fido2.Common.Extensions;

public static class LoggerExtensions
{
    [SuppressMessage("Usage", "CA2254:Template should be a static expression", Justification = "Message is forwarded from caller in a generic logging wrapper.")]
    public static void LogDebugIfEnabled(this ILogger logger, string? message, params object?[] args)
    {
        if (logger.IsEnabled(LogLevel.Debug))
        {
            logger.LogDebug(message, args);
        }
    }
}
