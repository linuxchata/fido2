using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
public class ChallengeGeneratorTests
{
    [Test]
    public void Get_ShouldReturn24BytesChallenge()
    {
        // Arrange
        var generator = new ChallengeGenerator();

        // Act
        var challenge = generator.Get();

        // Assert
        Assert.That(challenge.Length, Is.EqualTo(24));
    }

    [Test]
    public void Get_ShouldReturnDifferentValuesOnMultipleCalls()
    {
        // Arrange
        var generator = new ChallengeGenerator();

        // Act
        var challenge1 = generator.Get();
        var challenge2 = generator.Get();
        var challenge3 = generator.Get();

        // Assert
        Assert.That(challenge1, Is.Not.EqualTo(challenge2));
        Assert.That(challenge2, Is.Not.EqualTo(challenge3));
        Assert.That(challenge1, Is.Not.EqualTo(challenge3));
    }
}
