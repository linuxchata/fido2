using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
public class UserIdGeneratorTests
{
    private UserIdGenerator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new UserIdGenerator();
    }

    [Test]
    public void Get_WithoutSeed_ReturnsRandomBytes()
    {
        // Act
        var result1 = _sut.Get();
        var result2 = _sut.Get();

        // Assert
        Assert.That(result1, Has.Length.EqualTo(48));
        Assert.That(result2, Has.Length.EqualTo(48));
        Assert.That(result1, Is.Not.EqualTo(result2), "Generated IDs should be random");
    }

    [Test]
    public void Get_WithEmptySeed_ReturnsRandomBytes()
    {
        // Act
        var result = _sut.Get(string.Empty);

        // Assert
        Assert.That(result, Has.Length.EqualTo(48));
    }

    [Test]
    public void Get_WithWhiteSpaceSeed_ReturnsRandomBytes()
    {
        // Act
        var result = _sut.Get("   ");

        // Assert
        Assert.That(result, Has.Length.EqualTo(48));
    }

    [Test]
    public void Get_WithValidSeed_ReturnsDeterministicBytes()
    {
        // Arrange
        var seed = "AQIDBA=="; // Base64Url for [1,2,3,4]
        var expected = new byte[] { 65, 81, 73, 68, 66, 65, 61, 61 };

        // Act
        var result = _sut.Get(seed);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    [TestCase("Alex")]
    [TestCase("Alex Müller")]
    [TestCase("Émile")]
    [TestCase("Maëlys")]
    [TestCase("Benoît")]
    [TestCase("Jürg")]
    [TestCase("Übelmann")]
    [TestCase("Façien")]
    [TestCase("ßimon")]
    [TestCase("Éçalür")]
    [TestCase("Üßaria")]
    [TestCase("Cürßen")]
    [TestCase("Façéra")]
    [TestCase("ßlaüdré")]
    [TestCase("Çüméa")]
    [TestCase("Олександр")]
    [TestCase("Софія")]
    [TestCase("田中倫")]
    [TestCase("東京")]
    [TestCase("あいうえお")]
    [TestCase("アイウエオ")]
    [TestCase("😀🔥🍣")]
    public void Get_WithValidSeed_ReturnsNotEmptyBytes(string seed)
    {
        // Act
        var result = _sut.Get(seed);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.Not.Empty);
    }

    [Test]
    public void Get_WithSameSeed_ReturnsSameBytes()
    {
        // Arrange
        var seed = "AQIDBA==";

        // Act
        var result1 = _sut.Get(seed);
        var result2 = _sut.Get(seed);

        // Assert
        Assert.That(result1, Is.EqualTo(result2));
    }

    [Test]
    public void Get_WithLongSeed_ReturnsRandomBytes()
    {
        // Act
        var result = _sut.Get("ExtremelyLongSeedForUserIdentifierGenerationUsingHighEntropySecureAlgorithm");

        // Assert
        Assert.That(result, Has.Length.EqualTo(48));
    }
}