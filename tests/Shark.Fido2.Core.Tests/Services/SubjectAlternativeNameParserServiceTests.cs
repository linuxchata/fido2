using Shark.Fido2.Core.Services;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class SubjectAlternativeNameParserServiceTests
{
    private SubjectAlternativeNameParserService _sut;

    [SetUp]
    public void Setup()
    {
        _sut = new SubjectAlternativeNameParserService();
    }

    [Test]
    public void Parse_WhenSubjectAlternativeNameHasNameNotation_ThenReturnsTpmIssuer()
    {
        // Arrange
        var subjectAlternativeName = "Directory Address:TPMVersion=id:13 + TPMModel=NPCT6xx + TPMManufacturer=id:4E544300";

        // Act
        var result = _sut.Parse(subjectAlternativeName);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Manufacturer, Is.EqualTo("id:4E544300"));
        Assert.That(result.ManufacturerValue, Is.EqualTo("4E544300"));
        Assert.That(result.Model, Is.EqualTo("NPCT6xx"));
        Assert.That(result.Version, Is.EqualTo("id:13"));
    }

    [Test]
    public void Parse_WhenSubjectAlternativeNameHasNumericNotation_ThenReturnsTpmIssuer()
    {
        // Arrange
        var subjectAlternativeName = "DirName:/2.23.133.2.3=id:13+2.23.133.2.2=NPCT6xx+2.23.133.2.1=id:4E544300";

        // Act
        var result = _sut.Parse(subjectAlternativeName);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Manufacturer, Is.EqualTo("id:4E544300"));
        Assert.That(result.ManufacturerValue, Is.EqualTo("4E544300"));
        Assert.That(result.Model, Is.EqualTo("NPCT6xx"));
        Assert.That(result.Version, Is.EqualTo("id:13"));
    }
}
