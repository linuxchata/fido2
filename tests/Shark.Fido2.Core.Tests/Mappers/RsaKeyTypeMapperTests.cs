using System.Security.Cryptography;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Mappers;

[TestFixture]
internal class RsaKeyTypeMapperTests
{
    [TestCase(PublicKeyAlgorithm.Ps256, "SHA256", RSASignaturePaddingMode.Pss)]
    [TestCase(PublicKeyAlgorithm.Ps384, "SHA384", RSASignaturePaddingMode.Pss)]
    [TestCase(PublicKeyAlgorithm.Ps512, "SHA512", RSASignaturePaddingMode.Pss)]
    [TestCase(PublicKeyAlgorithm.Rs256, "SHA256", RSASignaturePaddingMode.Pkcs1)]
    [TestCase(PublicKeyAlgorithm.Rs384, "SHA384", RSASignaturePaddingMode.Pkcs1)]
    [TestCase(PublicKeyAlgorithm.Rs512, "SHA512", RSASignaturePaddingMode.Pkcs1)]
    [TestCase(PublicKeyAlgorithm.Rs1, "SHA1", RSASignaturePaddingMode.Pkcs1)]
    public void Get_WhenValidAlgorithm_ReturnsCorrectAlgorithm(
        PublicKeyAlgorithm algorithm,
        string expectedHashAlgorithmName,
        RSASignaturePaddingMode expectedRsaSignaturePaddingMode)
    {
        // Act
        var result = RsaKeyTypeMapper.Get((int)algorithm);

        // Assert
        Assert.That(result.HashAlgorithmName.Name, Is.EqualTo(expectedHashAlgorithmName));
        Assert.That(result.Padding!.Mode, Is.EqualTo(expectedRsaSignaturePaddingMode));
    }

    [Test]
    public void Get_WhenUnsupportedAlgorithm_ThrowsNotSupportedException()
    {
        // Arrange
        const int unsupportedAlgorithm = 999;

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => RsaKeyTypeMapper.Get(unsupportedAlgorithm));
    }
}