using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Tests.Responses;

[TestFixture]
internal class ServerResponseTests
{
    [Test]
    public void Create_WhenCalled_ThenReturnsServerResponseWithOkStatus()
    {
        // Act
        var result = ServerResponse.Create();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("ok"));
        Assert.That(result.ErrorMessage, Is.Null);
    }

    [Test]
    public void CreateFailed_WhenCalledWithoutErrorMessage_ThenReturnsServerResponseWithFailedStatus()
    {
        // Act
        var result = ServerResponse.CreateFailed();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.ErrorMessage, Is.Null);
    }

    [Test]
    public void CreateFailed_WhenCalledWithErrorMessage_ThenReturnsServerResponseWithFailedStatusAndErrorMessage()
    {
        // Arrange
        const string errorMessage = "Test error message";

        // Act
        var result = ServerResponse.CreateFailed(errorMessage);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.ErrorMessage, Is.EqualTo(errorMessage));
    }

    [Test]
    public void CreateFailed_WhenCalledWithNullErrorMessage_ThenReturnsServerResponseWithFailedStatusAndNullErrorMessage()
    {
        // Act
        var result = ServerResponse.CreateFailed(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.ErrorMessage, Is.Null);
    }

    [Test]
    public void CreateFailed_WhenCalledWithEmptyErrorMessage_ThenReturnsServerResponseWithFailedStatusAndEmptyErrorMessage()
    {
        // Act
        var result = ServerResponse.CreateFailed(string.Empty);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.ErrorMessage, Is.EqualTo(string.Empty));
    }

    [Test]
    public void Properties_WhenSetDirectly_ThenReturnExpectedValues()
    {
        // Arrange
        var result = new ServerResponse();
        const string status = "custom-status";
        const string errorMessage = "Custom error";

        // Act
        result.Status = status;
        result.ErrorMessage = errorMessage;

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo(status));
        Assert.That(result.ErrorMessage, Is.EqualTo(errorMessage));
    }

    [Test]
    public void Constructor_WhenCalled_ThenCreatesInstanceWithDefaultValues()
    {
        // Act
        var result = new ServerResponse();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.Null);
        Assert.That(result.ErrorMessage, Is.Null);
    }
}