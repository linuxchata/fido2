using Microsoft.Extensions.Time.Testing;
using Shark.Fido2.Metadata.Core.Validators;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Metadata.Core.Tests.Validators;

[TestFixture]
internal class CertificateValidatorTests
{
    private FakeTimeProvider _fakeTimeProvider = null!;

    private CertificateValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _fakeTimeProvider = new FakeTimeProvider();
        _fakeTimeProvider.SetUtcNow(new DateTimeOffset(2025, 8, 14, 10, 0, 0, TimeSpan.Zero));

        _sut = new CertificateValidator(_fakeTimeProvider);
    }

    [Test]
    public void ValidateX509Chain_WhenRootCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var allCertificates = CertificateDataReader.Read("Metadata.pem");

        var certificates = allCertificates.SkipLast(1).ToList();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateX509Chain(null!, certificates));
    }

    [Test]
    public void ValidateX509Chain_WhenCertificatesAreNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var allCertificates = CertificateDataReader.Read("Metadata.pem");

        var rootCertificate = allCertificates.LastOrDefault();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateX509Chain(rootCertificate, null!));
    }

    [Test]
    public void ValidateX509Chain_WhenCertificatesAreNotValid_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var allCertificates = CertificateDataReader.Read("Metadata.pem");

        var rootCertificate = allCertificates.LastOrDefault();
        var certificates = allCertificates.SkipLast(2).ToList();

        _fakeTimeProvider.SetUtcNow(new DateTimeOffset(2030, 8, 14, 10, 0, 0, TimeSpan.Zero));

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => _sut.ValidateX509Chain(rootCertificate, certificates));
    }

    [Test]
    public void ValidateX509Chain_WhenCertificatesAreValid_ThenDoesNotThrowException()
    {
        // Arrange
        var allCertificates = CertificateDataReader.Read("Metadata.pem");

        var rootCertificate = allCertificates.LastOrDefault();
        var certificates = allCertificates.SkipLast(1).ToList();

        // Act & Assert
        _sut.ValidateX509Chain(rootCertificate, certificates);
    }
}
