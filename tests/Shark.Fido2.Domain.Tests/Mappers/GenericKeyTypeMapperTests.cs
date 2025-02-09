using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Domain.Tests.Mappers;

[TestFixture]
internal class GenericKeyTypeMapperTests
{
    [Test]
    public void Get_WhenKeyTypeIsRsa_ThenReturnsCorrectHashAlgorithm()
    {
        // Arrange
        var keyType = (int)KeyTypeEnum.Rsa;
        var publicKeyAlgorithm = (int)PublicKeyAlgorithm.Ps256;

        // Act
        var result = GenericKeyTypeMapper.Get(keyType, publicKeyAlgorithm);

        // Assert
        Assert.That(result, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Get_WhenKeyTypeIsEc2_ThenReturnsCorrectHashAlgorithm()
    {
        // Arrange
        var keyType = (int)KeyTypeEnum.Ec2;
        var publicKeyAlgorithm = (int)PublicKeyAlgorithm.Es256;

        // Act
        var result = GenericKeyTypeMapper.Get(keyType, publicKeyAlgorithm);

        // Assert
        Assert.That(result, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Get_WhenKeyTypeIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Arrange
        var keyType = 999;
        var publicKeyAlgorithm = (int)PublicKeyAlgorithm.Ps256;

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => GenericKeyTypeMapper.Get(keyType, publicKeyAlgorithm));
    }
}
