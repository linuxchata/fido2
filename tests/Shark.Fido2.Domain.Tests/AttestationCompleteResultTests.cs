namespace Shark.Fido2.Domain.Tests;

[TestFixture]
internal class AttestationCompleteResultTests
{
    [Test]
    public void Create_ShouldReturnValidResult()
    {
        // Act
        var result = AssertionCompleteResult.Create();

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Create_WhenFailure_ShouldReturnInvalidResultWithMessage()
    {
        // Arrange
        var expectedMessage = "Authentication failed";

        // Act
        var result = AssertionCompleteResult.CreateFailure(expectedMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo(expectedMessage));
    }
}
