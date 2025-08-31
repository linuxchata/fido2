using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class Ec2CryptographyValidatorTests
{
    private readonly byte[] _data = Encoding.UTF8.GetBytes("test data");
    private readonly byte[] _invalidSignature = [0x01, 0x02, 0x03];

    private ECDsa _ecdsa;
    private byte[] _signature;
    private X509Certificate2 _certificate;
    private CredentialPublicKey _credentialPublicKey;

    private Ec2CryptographyValidator _sut;

    [SetUp]
    public void Setup()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = _ecdsa.ExportParameters(false);
        _credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Ec2,
            Algorithm = (int)CoseAlgorithm.Es256,
            XCoordinate = parameters.Q.X!,
            YCoordinate = parameters.Q.Y!,
        };

        _signature = _ecdsa.SignData(_data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var certRequest = new CertificateRequest("CN=Test", _ecdsa, HashAlgorithmName.SHA256);
        _certificate = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        _sut = new Ec2CryptographyValidator();
    }

    [TearDown]
    public void TearDown()
    {
        _ecdsa.Dispose();
        _certificate.Dispose();
    }

    [Test]
    public void IsValid_WhenAlgorithmIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Arrange
        _credentialPublicKey.Algorithm = 999; // Unsupported algorithm

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => _sut.IsValid(_data, _invalidSignature, _credentialPublicKey));
    }

    [Test]
    public void IsValid_WhenCertificateHasNoEcdsaKey_ThenThrowsArgumentException()
    {
        // Arrange
        using var rsa = RSA.Create();
        var certificateRequest = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var signature = rsa.SignData(_data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.IsValid(_data, _invalidSignature, _credentialPublicKey, certificate));
    }

    [Test]
    public void IsValid_WhenWithAttestationCertificateAndSignatureIsInvalid_ThenReturnsFalse()
    {
        // Act
        var result = _sut.IsValid(_data, _invalidSignature, _credentialPublicKey, _certificate);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsValid_WhenWithAttestationCertificateAndSignatureIsValid_ThenReturnsTrue()
    {
        // Act
        var result = _sut.IsValid(_data, _signature, _credentialPublicKey, _certificate);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsValid_WhenWithCredentialPublicKeyAndSignatureIsInvalid_ThenReturnsFalse()
    {
        // Act
        var result = _sut.IsValid(_data, _invalidSignature, _credentialPublicKey);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsValid_WhenWithCredentialPublicKeyAndSignatureIsValid_ThenReturnsTrue()
    {
        // Act
        var result = _sut.IsValid(_data, _signature, _credentialPublicKey);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndCertificateIsNull_ThenReturnsFalse()
    {
        // Act
        var result = _sut.IsValid(_data, _invalidSignature, (int)CoseAlgorithm.Es256, null!);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndAlgorithmIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Act & Assert
        Assert.Throws<NotSupportedException>(() => _sut.IsValid(_data, _invalidSignature, 999, _certificate));
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndCertificateHasNoEcdsaKey_ThenThrowsArgumentException()
    {
        // Arrange
        using var rsa = RSA.Create();
        var certificateRequest = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var signature = rsa.SignData(_data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.IsValid(_data, signature, (int)CoseAlgorithm.Es256, certificate));
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndSignatureIsInvalid_ThenReturnsFalse()
    {
        // Act
        var result = _sut.IsValid(_data, _invalidSignature, (int)CoseAlgorithm.Es256, _certificate);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndSignatureIsValid_ThenReturnsTrue()
    {
        // Act
        var result = _sut.IsValid(_data, _signature, (int)CoseAlgorithm.Es256, _certificate);

        // Assert
        Assert.That(result, Is.True);
    }
}