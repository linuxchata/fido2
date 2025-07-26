using System.Security.Cryptography;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Mappers;

[TestFixture]
internal class Ec2KeyTypeMapperTests
{
    [Test]
    public void Get_WhenEs256_ThenReturnsCorrectAlgorithm()
    {
        // Arrange
        var algorithm = (int)CoseAlgorithm.Es256;

        // Act
        var result = Ec2KeyTypeMapper.Get(algorithm);

        // Assert
        Assert.That(result!.HashAlgorithmName, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(result.Curve.Oid.FriendlyName, Is.EqualTo(ECCurve.NamedCurves.nistP256.Oid.FriendlyName));
        Assert.That(result.Curve.Oid.Value, Is.EqualTo(ECCurve.NamedCurves.nistP256.Oid.Value));
    }

    [Test]
    public void Get_WhenEs384_ThenReturnsCorrectAlgorithm()
    {
        // Arrange
        var algorithm = (int)CoseAlgorithm.Es384;

        // Act
        var result = Ec2KeyTypeMapper.Get(algorithm);

        // Assert
        Assert.That(result!.HashAlgorithmName, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(result.Curve.Oid.FriendlyName, Is.EqualTo(ECCurve.NamedCurves.nistP384.Oid.FriendlyName));
        Assert.That(result.Curve.Oid.Value, Is.EqualTo(ECCurve.NamedCurves.nistP384.Oid.Value));
    }

    [Test]
    public void Get_WhenEs512_ThenReturnsCorrectAlgorithm()
    {
        // Arrange
        var algorithm = (int)CoseAlgorithm.Es512;

        // Act
        var result = Ec2KeyTypeMapper.Get(algorithm);

        // Assert
        Assert.That(result!.HashAlgorithmName, Is.EqualTo(HashAlgorithmName.SHA512));
        Assert.That(result.Curve.Oid.FriendlyName, Is.EqualTo(ECCurve.NamedCurves.nistP521.Oid.FriendlyName));
        Assert.That(result.Curve.Oid.Value, Is.EqualTo(ECCurve.NamedCurves.nistP521.Oid.Value));
    }

    [Test]
    public void Get_WhenEs256K_ThenReturnsCorrectAlgorithm()
    {
        // Arrange
        var algorithm = (int)CoseAlgorithm.Es256K;

        // Act
        var result = Ec2KeyTypeMapper.Get(algorithm);

        // Assert
        Assert.That(result!.HashAlgorithmName, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(result.Curve.Oid.FriendlyName, Is.EqualTo("secp256k1"));
        Assert.That(result.Curve.Oid.Value, Is.EqualTo("1.3.132.0.10"));
    }

    [Test]
    public void Get_WhenAlgorithmIsNotSupported_ThenThrowsReturnsNull()
    {
        // Arrange
        const int algorithm = 999;

        // Act
        var result = Ec2KeyTypeMapper.Get(algorithm);

        // Assert
        Assert.That(result, Is.Null);
    }
}