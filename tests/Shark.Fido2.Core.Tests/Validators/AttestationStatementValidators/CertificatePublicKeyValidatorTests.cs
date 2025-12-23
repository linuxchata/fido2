using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class CertificatePublicKeyValidatorTests
{
    private CertificatePublicKeyValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new CertificatePublicKeyValidator();
    }

    [Test]
    public void Validate_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var credentialPublicKey = new CredentialPublicKey();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(null!, credentialPublicKey));
    }

    [Test]
    public void Validate_WhenCredentialPublicKeyIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(certificate, null!));
    }

    [Test]
    public void Validate_WhenRsaPublicKeyMatches_ThenReturnsValidResult()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Rsa,
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent,
        };

        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = _sut.Validate(certificate, credentialPublicKey);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WhenRsaModulusMismatches_ThenReturnsInvalidResult()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Rsa,
            Modulus = new byte[parameters.Modulus!.Length], // Wrong modulus
            Exponent = parameters.Exponent,
        };

        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = _sut.Validate(certificate, credentialPublicKey);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Certificate public key is not valid"));
    }

    [Test]
    public void Validate_WhenRsaExponentMismatches_ThenReturnsInvalidResult()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Rsa,
            Modulus = parameters.Modulus,
            Exponent = [0, 0, 0], // Wrong exponent
        };

        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = _sut.Validate(certificate, credentialPublicKey);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Certificate public key is not valid"));
    }

    [Test]
    public void Validate_WhenEc2PublicKeyMatches_ThenReturnsValidResult()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(false);
        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Ec2,
            XCoordinate = parameters.Q.X,
            YCoordinate = parameters.Q.Y,
        };

        var request = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = _sut.Validate(certificate, credentialPublicKey);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WhenEc2XMismatches_ThenReturnsInvalidResult()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(false);
        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Ec2,
            XCoordinate = new byte[parameters.Q.X!.Length], // Wrong X
            YCoordinate = parameters.Q.Y,
        };

        var request = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = _sut.Validate(certificate, credentialPublicKey);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Certificate public key is not valid"));
    }

    [Test]
    public void Validate_WhenEc2YMismatches_ThenReturnsInvalidResult()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(false);
        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Ec2,
            XCoordinate = parameters.Q.X,
            YCoordinate = new byte[parameters.Q.Y!.Length], // Wrong Y
        };

        var request = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = _sut.Validate(certificate, credentialPublicKey);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Certificate public key is not valid"));
    }

    [Test]
    public void Validate_WhenKeyTypeIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Okp,
        };

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => _sut.Validate(certificate, credentialPublicKey));
    }
}
