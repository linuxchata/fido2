using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Services;

namespace Shark.Fido2.ConvenienceMetadata.Core.Tests.Services;

[TestFixture]
internal class ConvenienceMetadataReaderServiceTests
{
    private ConvenienceMetadataReaderService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new ConvenienceMetadataReaderService(NullLogger<ConvenienceMetadataReaderService>.Instance);
    }

    [Test]
    public void Read_WhenBlobIsNull_ThenThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Read(null!));
    }

    [Test]
    public void Read_WhenBlobIsEmpty_ThenThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Read(string.Empty));
    }

    [Test]
    public void Read_WhenBlobIsInvalidJson_ThenThrowsJsonException()
    {
        // Arrange
        var blob = "invalid-json";

        // Act & Assert
        Assert.Throws<JsonException>(() => _sut.Read(blob));
    }

    [Test]
    public void Read_WhenBlobIsNullJson_ThenThrowsInvalidDataException()
    {
        // Arrange
        var blob = "null";

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => _sut.Read(blob));
    }

    [Test]
    public void Read_WhenBlobIsValidJson_ThenReturnsPayload()
    {
        // Arrange
        var blob = """
        {
          "no": 1,
          "00000000-0000-0000-0000-000000000000": {
            "friendlyNames": {
              "en": "Test Authenticator"
            }
          }
        }
        """;

        // Act
        var result = _sut.Read(blob);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Entries, Has.Count.EqualTo(1));
        Assert.That(result.Entries.ContainsKey("00000000-0000-0000-0000-000000000000"), Is.True);
    }
}
