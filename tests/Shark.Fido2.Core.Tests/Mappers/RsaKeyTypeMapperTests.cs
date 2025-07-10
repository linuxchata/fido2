using System.Security.Cryptography;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Mappers;

[TestFixture]
internal class RsaKeyTypeMapperTests
{
    [TestCase(CoseAlgorithm.Ps256, "SHA256", RSASignaturePaddingMode.Pss)]
    [TestCase(CoseAlgorithm.Ps384, "SHA384", RSASignaturePaddingMode.Pss)]
    [TestCase(CoseAlgorithm.Ps512, "SHA512", RSASignaturePaddingMode.Pss)]
    [TestCase(CoseAlgorithm.Rs256, "SHA256", RSASignaturePaddingMode.Pkcs1)]
    [TestCase(CoseAlgorithm.Rs384, "SHA384", RSASignaturePaddingMode.Pkcs1)]
    [TestCase(CoseAlgorithm.Rs512, "SHA512", RSASignaturePaddingMode.Pkcs1)]
    [TestCase(CoseAlgorithm.Rs1, "SHA1", RSASignaturePaddingMode.Pkcs1)]
    public void Get_WhenValidAlgorithm_ReturnsCorrectAlgorithm(
        CoseAlgorithm algorithm,
        string expectedHashAlgorithmName,
        RSASignaturePaddingMode expectedRsaSignaturePaddingMode)
    {
        // Act
        var result = RsaKeyTypeMapper.Get((int)algorithm);

        // Assert
        Assert.That(result!.HashAlgorithmName.Name, Is.EqualTo(expectedHashAlgorithmName));
        Assert.That(result.Padding!.Mode, Is.EqualTo(expectedRsaSignaturePaddingMode));
    }

    [Test]
    public void Get_WhenAlgorithmIsNotSupported_ThrowsReturnsNull()
    {
        // Arrange
        const int algorithm = 999;

        // Act
        var result = RsaKeyTypeMapper.Get(algorithm);

        // Assert
        Assert.That(result, Is.Null);
    }
}