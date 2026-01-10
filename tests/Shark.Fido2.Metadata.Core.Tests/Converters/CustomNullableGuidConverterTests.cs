using System.Text.Json;
using Shark.Fido2.Metadata.Core.Converters;

namespace Shark.Fido2.Metadata.Core.Tests.Converters;

[TestFixture]
public class CustomNullableGuidConverterTests
{
    private CustomNullableGuidConverter _converter;
    private JsonSerializerOptions _options;

    [SetUp]
    public void SetUp()
    {
        _converter = new CustomNullableGuidConverter();
        _options = new JsonSerializerOptions();
    }

    [Test]
    public void Read_WhenValidGuid_ThenReturnsGuid()
    {
        // Arrange
        var guid = Guid.NewGuid();
        var json = $"\"{guid}\"";

        // Act
        var result = ReadFromJson(json);

        // Assert
        Assert.That(result, Is.EqualTo(guid));
    }

    [Test]
    public void Read_WhenNull_ThenReturnsNull()
    {
        // Act
        var result = ReadFromJson("null");

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    [TestCase("\"\"")]
    [TestCase("\"   \"")]
    public void Read_WhenEmptyOrWhitespace_ThenReturnsNull(string json)
    {
        // Act
        var result = ReadFromJson(json);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Write_WhenGuid_ThenWritesStringValue()
    {
        // Arrange
        var guid = Guid.NewGuid();
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);

        // Act
        _converter.Write(writer, guid, _options);
        writer.Flush();

        // Assert
        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray());
        Assert.That(json, Is.EqualTo($"\"{guid}\""));
    }

    [Test]
    public void Write_WhenNull_ThenWritesNull()
    {
        // Arrange
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);

        // Act
        _converter.Write(writer, null, _options);
        writer.Flush();

        // Assert
        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray());
        Assert.That(json, Is.EqualTo("null"));
    }

    private Guid? ReadFromJson(string json)
    {
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        return _converter.Read(ref reader, typeof(Guid?), _options);
    }
}
