using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Domain.Tests.Mappers;

[TestFixture]
internal class TmpHashAlgorithmMapperTests
{
    [Test]
    public void Get_WhenUnsupportedAlgorithm_ThrowsNotSupportedException()
    {
        // Arrange
        var unsupportedAlgorithm = TpmAlgorithmEnum.TpmAlgorithmRsa;

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => TmpHashAlgorithmMapper.Get(unsupportedAlgorithm));
    }

    [TestCaseSource(nameof(HashAlgorithmTestCases))]
    public void Get_WhenValidAlgorithm_ReturnsExpectedHashAlgorithmName(TpmAlgorithmEnum tpmAlgorithm, HashAlgorithmName expectedHashAlgorithmName)
    {
        // Act
        var result = TmpHashAlgorithmMapper.Get(tpmAlgorithm);

        // Assert
        Assert.That(result, Is.EqualTo(expectedHashAlgorithmName));
    }

    private static IEnumerable<TestCaseData> HashAlgorithmTestCases()
    {
        yield return new TestCaseData(TpmAlgorithmEnum.TpmAlgorithmSha1, HashAlgorithmName.SHA1);
        yield return new TestCaseData(TpmAlgorithmEnum.TpmAlgorithmSha256, HashAlgorithmName.SHA256);
        yield return new TestCaseData(TpmAlgorithmEnum.TpmAlgorithmSha384, HashAlgorithmName.SHA384);
        yield return new TestCaseData(TpmAlgorithmEnum.TpmAlgorithmSha512, HashAlgorithmName.SHA512);
    }
}
