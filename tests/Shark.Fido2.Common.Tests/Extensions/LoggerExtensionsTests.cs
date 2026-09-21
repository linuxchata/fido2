using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Moq;
using Shark.Fido2.Common.Extensions;

namespace Shark.Fido2.Common.Tests.Extensions;

[TestFixture]
[SuppressMessage("Performance", "CA1873:Avoid potentially expensive logging", Justification = "Tests deliberately call the logging extension directly.")]
internal class LoggerExtensionsTests
{
    [Test]
    [TestCase("arg1")]
    [TestCase("arg1\r\n")]
    [TestCase("arg1\n")]
    [TestCase("arg1\r")]
    public void LogInformationIfEnabled_WhenInformationEnabled_InvokesFactoryAndLogs(string argument)
    {
        // Arrange
        var loggerMock = new Mock<ILogger>();
        loggerMock.Setup(l => l.IsEnabled(LogLevel.Information)).Returns(true);

        // Act
        loggerMock.Object.LogInformationIfEnabled("Message {Value}", argument);

        // Assert
        loggerMock.Verify(
            l => l.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((state, t) => state.ToString()!.TrimEnd() == "Message arg1"),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Test]
    public void LogInformationIfEnabled_WhenInformationDisabled_SkipsFactoryAndLogging()
    {
        // Arrange
        var loggerMock = new Mock<ILogger>();
        loggerMock.Setup(l => l.IsEnabled(LogLevel.Information)).Returns(false);

        // Act
        loggerMock.Object.LogInformationIfEnabled("Message {Value}", "arg1");

        // Assert
        loggerMock.Verify(
            l => l.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Never);
    }

    [Test]
    [TestCase("arg1")]
    [TestCase("arg1\r\n")]
    [TestCase("arg1\n")]
    [TestCase("arg1\r")]
    public void LogDebugIfEnabled_WhenDebugEnabled_InvokesFactoryAndLogs(string argument)
    {
        // Arrange
        var loggerMock = new Mock<ILogger>();
        loggerMock.Setup(l => l.IsEnabled(LogLevel.Debug)).Returns(true);

        // Act
        loggerMock.Object.LogDebugIfEnabled("Message {Value}", argument);

        // Assert
        loggerMock.Verify(
            l => l.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((state, t) => state.ToString()!.TrimEnd() == "Message arg1"),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Test]
    public void LogDebugIfEnabled_WhenDebugDisabled_SkipsFactoryAndLogging()
    {
        // Arrange
        var loggerMock = new Mock<ILogger>();
        loggerMock.Setup(l => l.IsEnabled(LogLevel.Debug)).Returns(false);

        // Act
        loggerMock.Object.LogDebugIfEnabled("Message {Value}", "arg1");

        // Assert
        loggerMock.Verify(
            l => l.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Never);
    }
}
