using System.Text.Json;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Tests.Enums;

[TestFixture]
internal class TokenBindingStatusConverterTests
{
    private TokenBindingStatusConverter _converter;
    private JsonSerializerOptions _options;

    [SetUp]
    public void SetUp()
    {
        _converter = new TokenBindingStatusConverter();
        _options = new JsonSerializerOptions();
    }

    [Test]
    [TestCase("\"present\"", TokenBindingStatus.Present)]
    [TestCase("\"supported\"", TokenBindingStatus.Supported)]
    [TestCase("\"not-supported\"", TokenBindingStatus.NotSupported)]
    public void Read_WhenValueIsValid_ThenReturnsCorrectEnum(string json, TokenBindingStatus expectedTokenBindingStatus)
    {
        // Act
        var result = ReadFromJson(json);

        // Assert
        Assert.That(result, Is.EqualTo(expectedTokenBindingStatus));
    }

    [Test]
    [TestCase("\"invalid\"")]
    [TestCase("\"unknown\"")]
    [TestCase("\"\"")]
    public void Read_WhenValueIsInvalid_ThenThrowsJsonException(string json)
    {
        // Act & Assert
        var exception = Assert.Throws<JsonException>(() => ReadFromJson(json));

        Assert.That(exception.Message, Does.Contain("Unknown TokenBindingStatus value"));
    }

    [Test]
    public void Read_WhenValueIsNull_ThenThrowsJsonException()
    {
        // Act & Assert
        var exception = Assert.Throws<JsonException>(() => ReadFromJson("null"));

        Assert.That(exception.Message, Does.Contain("Unknown TokenBindingStatus value"));
    }

    [Test]
    [TestCase(TokenBindingStatus.Present, "present")]
    [TestCase(TokenBindingStatus.Supported, "supported")]
    [TestCase(TokenBindingStatus.NotSupported, "not-supported")]
    public void Write_WhenEnumItemIsValid_ThenWritesCorrectString(TokenBindingStatus tokenBindingStatus, string expectedValue)
    {
        // Arrange
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);

        // Act
        _converter.Write(writer, tokenBindingStatus, _options);
        writer.Flush();

        // Assert
        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray());
        Assert.That(json, Is.EqualTo($"\"{expectedValue}\""));
    }

    [Test]
    public void Write_WhenEnumItemIsInvalid_ThenThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);
        var invalidValue = (TokenBindingStatus)999;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => _converter.Write(writer, invalidValue, _options));

        Assert.That(exception.ParamName, Is.EqualTo("value"));
        Assert.That(exception.Message, Does.Contain("Unknown TokenBindingStatus value"));
    }

    [Test]
    [TestCase(TokenBindingStatus.Present, "\"present\"")]
    [TestCase(TokenBindingStatus.Supported, "\"supported\"")]
    [TestCase(TokenBindingStatus.NotSupported, "\"not-supported\"")]
    public void JsonSerialization_WhenRoundTrip_ThenReturnsValue(TokenBindingStatus tokenBindingStatus, string expectedJson)
    {
        // Arrange
        var options = new JsonSerializerOptions();
        options.Converters.Add(new TokenBindingStatusConverter());

        // Act
        var json = JsonSerializer.Serialize(tokenBindingStatus, options);
        var deserialized = JsonSerializer.Deserialize<TokenBindingStatus>(json, options);

        // Assert
        Assert.That(json, Is.EqualTo(expectedJson));
        Assert.That(deserialized, Is.EqualTo(tokenBindingStatus));
    }

    private TokenBindingStatus ReadFromJson(string json)
    {
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        return _converter.Read(ref reader, typeof(TokenBindingStatus), _options);
    }
}