using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class OkpCryptographyValidatorTests
{
    private readonly byte[] _data = Encoding.UTF8.GetBytes("test data");
    private readonly byte[] _invalidSignature = [0x01, 0x02, 0x03];

    private Ed25519KeyPairGenerator _keyPairGenerator;
    private Ed25519PrivateKeyParameters _privateKey;
    private Ed25519PublicKeyParameters _publicKey;
    private byte[] _signature;
    private CredentialPublicKey _credentialPublicKey;

    private OkpCryptographyValidator _sut;

    [SetUp]
    public void Setup()
    {
        _keyPairGenerator = new Ed25519KeyPairGenerator();
        _keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));

        var keyPair = _keyPairGenerator.GenerateKeyPair();
        _privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;
        _publicKey = (Ed25519PublicKeyParameters)keyPair.Public;

        _credentialPublicKey = new CredentialPublicKey
        {
            KeyType = (int)KeyType.Okp,
            Algorithm = (int)CoseAlgorithm.EdDsa,
            Curve = (int)EllipticCurveKey.Ed25519,
            XCoordinate = _publicKey.GetEncoded(),
        };

        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(_data, 0, _data.Length);
        _signature = signer.GenerateSignature();

        _sut = new OkpCryptographyValidator();
    }

    [Test]
    public void IsValid_WhenAlgorithmIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Arrange
        _credentialPublicKey.Algorithm = 999; // Unsupported algorithm

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => _sut.IsValid(_data, _signature, _credentialPublicKey));
    }

    [Test]
    public void IsValid_WhenCurveIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Arrange
        _credentialPublicKey.Curve = 999; // Unsupported curve

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => _sut.IsValid(_data, _signature, _credentialPublicKey));
    }

    [Test]
    public void IsValid_WhenSignatureIsInvalid_ThenReturnsFalse()
    {
        // Act
        var result = _sut.IsValid(_data, _invalidSignature, _credentialPublicKey);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsValid_WhenSignatureIsValid_ThenReturnsTrue()
    {
        // Act
        var result = _sut.IsValid(_data, _signature, _credentialPublicKey);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsValid_WhenDataIsDifferent_ThenReturnsFalse()
    {
        // Arrange
        var differentData = Encoding.UTF8.GetBytes("different test data");

        // Act
        var result = _sut.IsValid(differentData, _signature, _credentialPublicKey);

        // Assert
        Assert.That(result, Is.False);
    }
}