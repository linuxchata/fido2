#pragma warning disable CA1873 // Avoid potentially expensive logging

using Microsoft.Extensions.Logging;
using Moq;
using Shark.Fido2.Common.Extensions;

namespace Shark.Fido2.Common.Tests.Extensions;

[TestFixture]
internal class LoggerExtensionsTests
{
    [Test]
    public void LogDebugIfEnabled_WhenDebugEnabled_InvokesFactoryAndLogs()
    {
        // Arrange
        var loggerMock = new Mock<ILogger>();
        loggerMock.Setup(l => l.IsEnabled(LogLevel.Debug)).Returns(true);
        var factoryCalled = false;

        object[] ArgsFactory()
        {
            factoryCalled = true;
            return ["arg1"];
        }

        // Act
        loggerMock.Object.LogDebugIfEnabled("Message {Value}", (Func<object[]>)ArgsFactory);

        // Assert
        Assert.That(factoryCalled, Is.True);
        loggerMock.Verify(
            l => l.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
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
        var factoryCalled = false;

        object[] ArgsFactory()
        {
            factoryCalled = true;
            return ["arg1"];
        }

        // Act
        loggerMock.Object.LogDebugIfEnabled("Message {Value}", (Func<object[]>)ArgsFactory);

        // Assert
        Assert.That(factoryCalled, Is.False); // proves expensive work was avoided
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
