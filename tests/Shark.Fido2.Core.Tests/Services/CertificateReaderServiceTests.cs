using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Services;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class CertificateReaderTests
{
    private const string EmbeddedCertificateName = "certificate.pem";

    private CertificateReaderService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new CertificateReaderService();
    }

    [Test]
    public void Read_WhenEmbeddedCertificateNameIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Read(null!));
    }

    [TestCase("")]
    [TestCase("   ")]
    public void Read_WhenEmbeddedCertificateNameIsEmpty_ThenThrowsArgumentException(string embeddedCertificateName)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Read(embeddedCertificateName));
    }

    [Test]
    public void Read_WhenEmbeddedCertificateIsEmpty_ThenThrowsFileNotFoundException()
    {
        // Arrange

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() => _sut.ParseCertiticate(EmbeddedCertificateName, []));
    }

    [Test]
    public void Read_WhenEmbeddedCertificateHasMultipleLines_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var certificates = new List<string>
        {
            "MIICEjCCAZmgAw...",
            "MIICEjCCAZmgAw...",
        };

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => _sut.ParseCertiticate(EmbeddedCertificateName, certificates));
    }

    [Test]
    public void Read_WhenEmbeddedCertificateHasInvalidBase64_ThenThrowsFormatException()
    {
        // Arrange
        var certificates = new List<string>
        {
            "not-a-valid-base64",
        };

        // Act & Assert
        Assert.Throws<FormatException>(() => _sut.ParseCertiticate(EmbeddedCertificateName, certificates));
    }

    [Test]
    public void Read_WhenEmbeddedCertificateHasValidBase64Certificate_ThenReturnsCertificate()
    {
        // Act
        var result = _sut.Read("Apple_WebAuthn_Root_CA.pem");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.TypeOf<X509Certificate2>());
    }
}
