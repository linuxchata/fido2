using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class RsaCryptographyValidatorTests
{
    private readonly byte[] _data = Encoding.UTF8.GetBytes("test data");
    private readonly byte[] _invalidSignature = [0x01, 0x02, 0x03];

    private RSA _rsa;
    private byte[] _signature;
    private X509Certificate2 _certificate;
    private CredentialPublicKey _credentialPublicKey;

    private RsaCryptographyValidator _sut;

    [SetUp]
    public void Setup()
    {
        _rsa = RSA.Create(2048);
        var parameters = _rsa.ExportParameters(false);
        _credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Rsa,
            Algorithm = (int)CoseAlgorithm.Rs256,
            Modulus = parameters.Modulus!,
            Exponent = parameters.Exponent!,
        };

        _signature = _rsa.SignData(_data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var certRequest = new CertificateRequest("CN=Test", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _certificate = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        _sut = new RsaCryptographyValidator();
    }

    [TearDown]
    public void TearDown()
    {
        _rsa.Dispose();
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
    public void IsValid_WhenCertificateHasNoRsaKey_ThenThrowsArgumentException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certificateRequest = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var signature = ecdsa.SignData(_data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

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
        var result = _sut.IsValid(_data, _invalidSignature, (int)CoseAlgorithm.Rs256, null!);

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
    public void IsValid_WhenWithAlgorithmAndCertificateAndCertificateHasNoRsaKey_ThenThrowsArgumentException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certificateRequest = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var signature = ecdsa.SignData(_data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.IsValid(_data, signature, (int)CoseAlgorithm.Rs256, certificate));
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndSignatureIsInvalid_ThenReturnsFalse()
    {
        // Act
        var result = _sut.IsValid(_data, _invalidSignature, (int)CoseAlgorithm.Rs256, _certificate);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsValid_WhenWithAlgorithmAndCertificateAndSignatureIsValid_ThenReturnsTrue()
    {
        // Act
        var result = _sut.IsValid(_data, _signature, (int)CoseAlgorithm.Rs256, _certificate);

        // Assert
        Assert.That(result, Is.True);
    }
}