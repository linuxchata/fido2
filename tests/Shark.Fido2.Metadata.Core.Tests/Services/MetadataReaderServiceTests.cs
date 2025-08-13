using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Services;

namespace Shark.Fido2.Metadata.Core.Tests.Services;

[TestFixture]
internal class MetadataReaderServiceTests
{
    private const string ValidMetadataBlobLocation = "https://example.com/metadata";

    private CancellationToken _cancellationToken;
    private Mock<X509Certificate2> _rootCertificateMock;

    private Mock<IHttpClientRepository> _httpClientRepositoryMock;
    private Mock<ICertificateValidator> _certificateValidatorMock;
    private Mock<IOptions<MetadataServiceConfiguration>> _optionsMock;

    private MetadataReaderService _sut;

    [SetUp]
    public void Setup()
    {
        _cancellationToken = CancellationToken.None;
        _rootCertificateMock = new Mock<X509Certificate2>();

        _httpClientRepositoryMock = new Mock<IHttpClientRepository>();
        _certificateValidatorMock = new Mock<ICertificateValidator>();
        _optionsMock = new Mock<IOptions<MetadataServiceConfiguration>>();

        var configuration = new MetadataServiceConfiguration
        {
            MetadataBlobLocation = ValidMetadataBlobLocation,
            MaximumTokenSizeInBytes = 1024 * 1024,
        };

        _optionsMock.Setup(x => x.Value).Returns(configuration);

        _sut = new MetadataReaderService(
            _httpClientRepositoryMock.Object,
            _certificateValidatorMock.Object,
            _optionsMock.Object);
    }

    [Test]
    public void ValidateAndRead_WhenMetadataBlobIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.ValidateAndRead(
            null!,
            _rootCertificateMock.Object,
            _cancellationToken));
    }

    [Test]
    [TestCase("")]
    [TestCase("   ")]
    public void ValidateAndRead_WhenMetadataBlobIsEmpty_ThenThrowsArgumentException(string metadataBlob)
    {
        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(() => _sut.ValidateAndRead(
            metadataBlob,
            _rootCertificateMock.Object,
            _cancellationToken));
    }

    [Test]
    public void ValidateAndRead_WhenRootCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature";

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.ValidateAndRead(
            invalidJwt,
            null!,
            _cancellationToken));
    }

    [Test]
    public void ValidateAndRead_WhenMetadataBlobIsInvalidJwt_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var invalidJwt = "not.a.valid.jwt";

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.ValidateAndRead(
            invalidJwt,
            _rootCertificateMock.Object,
            _cancellationToken));
    }

    [Test]
    public void ValidateAndRead_WhenMetadataBlobIsNotJwtFormat_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var notJwt = "this-is-not-a-jwt-at-all";

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.ValidateAndRead(
            notJwt,
            _rootCertificateMock.Object,
            _cancellationToken));
    }

    [Test]
    public void ValidateAndRead_WhenMetadataBlobHasInvalidFormat_ThenThrowsArgumentException()
    {
        // Arrange
        var malformedJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.invalid.signature";

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(() => _sut.ValidateAndRead(
            malformedJwt,
            _rootCertificateMock.Object,
            _cancellationToken));
    }

    [Test]
    public void ValidateAndRead_WhenJwtHeaderIsMissing_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var jwtWithoutHeader = ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature";

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.ValidateAndRead(
            jwtWithoutHeader,
            _rootCertificateMock.Object,
            _cancellationToken));
    }

    [Test]
    public void ValidateAndRead_WhenJwtPayloadIsMissing_ThenThrowsInvalidOperationException()
    {
        // Arrange
        var jwtWithoutPayload = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..signature";

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.ValidateAndRead(
            jwtWithoutPayload,
            _rootCertificateMock.Object,
            _cancellationToken));
    }
}