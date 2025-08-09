using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Tests.DataReaders;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class CertificateReaderTests
{
    private const string FileName = "certificate.pem";

    private string _directory = null!;

    private CertificateReaderService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_directory);

        _sut = new CertificateReaderService();
    }

    [TearDown]
    public void Cleanup()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Test]
    public void Read_WhenFileNameIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Read(null!, _directory));
    }

    [TestCase("")]
    [TestCase("   ")]
    public void Read_WhenFileNameIsEmpty_ThenThrowsArgumentException(string fileName)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Read(fileName, _directory));
    }

    [Test]
    public void Read_WhenFileIsEmpty_ThenThrowsFileNotFoundException()
    {
        // Arrange
        var filePath = Path.Combine(_directory, FileName);
        File.WriteAllText(filePath, string.Empty);

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() => _sut.Read(FileName, _directory));
    }

    [Test]
    public void Read_WhenFileHasMultipleLines_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var filePath = Path.Combine(_directory, FileName);
        File.WriteAllLines(filePath, ["line1", "line2"]);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => _sut.Read(FileName, _directory));
    }

    [Test]
    public void Read_WhenFileHasValidBase64Certificate_ThenReturnsCertificate()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("FidoU2f.pem");
        var certificate = certificates[0].Export(X509ContentType.Cert);
        var base64 = Convert.ToBase64String(certificate);

        var filePath = Path.Combine(_directory, FileName);
        File.WriteAllText(filePath, base64);

        // Act
        var result = _sut.Read(FileName, _directory);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.TypeOf<X509Certificate2>());
    }

    [Test]
    public void Read_WhenFileHasInvalidBase64_ThenThrowsFormatException()
    {
        // Arrange
        var filePath = Path.Combine(_directory, FileName);
        File.WriteAllText(filePath, "not-a-valid-base64");

        // Act & Assert
        Assert.Throws<FormatException>(() => _sut.Read(FileName, _directory));
    }
}
