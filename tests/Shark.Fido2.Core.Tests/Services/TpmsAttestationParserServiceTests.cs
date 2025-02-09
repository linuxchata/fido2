using Shark.Fido2.Core.Services;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class TpmsAttestationParserServiceTests
{
    private TpmsAttestationParserService _sut;

    [SetUp]
    public void Setup()
    {
        _sut = new TpmsAttestationParserService();
    }

    [Test]
    public void Parse_WhenCertInfoIsValid_ThenReturnsTrue()
    {
        // Arrange
        var certInfoBase64 = "/1RDR4AXACIAC7xZ9N/ZpqQtw7hmr/LfDRmCa78BS2erCtbrsXYwa4AHABSsnz8FacZi+wkUkfHu4xjG8MPfmwAAAAGxWkjHaED549jznwUBqeDEpT+7xBMAIgALcSGuv6a5r9BwMvQvCSXg7GdAjdWZpXv6D4DH8VYBCE8AIgALAVI0eQ/AAZjNvrhUEMK2q4wxuwIFOnHIDF0Qljhf47Q=";
        var certInfo = Convert.FromBase64String(certInfoBase64);

        // Act
        var result = _sut.Parse(certInfo, out var tpmsAttestation);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(tpmsAttestation.Magic, Is.EqualTo(0xff544347));
        Assert.That(tpmsAttestation.Type, Is.EqualTo(0x8017));
        Assert.That(tpmsAttestation.ExtraData, Is.Not.Null);
        Assert.That(tpmsAttestation.Attested.Name, Is.Not.Null);
    }
}