using System.Security.Cryptography;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Mappers;

[TestFixture]
internal class GenericKeyTypeMapperTests
{
    [Test]
    public void Get_WhenRsaAlgorithm_ThenReturnsCorrectKeyTypeAndHashAlgorithm()
    {
        // Arrange
        var coseAlgorithm = (int)CoseAlgorithm.Ps256;

        // Act
        var (keyType, hashAlgorithmName) = GenericKeyTypeMapper.Get(coseAlgorithm);

        // Assert
        Assert.That(keyType, Is.EqualTo(KeyTypeEnum.Rsa));
        Assert.That(hashAlgorithmName, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Get_WhenEc2Algorithm_ThenReturnsCorrectKeyTypeAndHashAlgorithm()
    {
        // Arrange
        var coseAlgorithm = (int)CoseAlgorithm.Es256;

        // Act
        var (keyType, hashAlgorithmName) = GenericKeyTypeMapper.Get(coseAlgorithm);

        // Assert
        Assert.That(keyType, Is.EqualTo(KeyTypeEnum.Ec2));
        Assert.That(hashAlgorithmName, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Get_WhenAlgorithmIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Arrange
        const int algorithm = 999;

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => GenericKeyTypeMapper.Get(algorithm));
    }
}
