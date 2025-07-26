using System.Security.Cryptography;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Mappers;

[TestFixture]
internal class TmpHashAlgorithmMapperTests
{
    [Test]
    public void Get_WhenUnsupportedAlgorithm_ThenThrowsNotSupportedException()
    {
        // Arrange
        var unsupportedAlgorithm = TpmAlgorithm.TpmAlgorithmRsa;

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => TmpHashAlgorithmMapper.Get(unsupportedAlgorithm));
    }

    [TestCaseSource(nameof(HashAlgorithmTestCases))]
    public void Get_WhenValidAlgorithm_ThenReturnsExpectedHashAlgorithmName(TpmAlgorithm tpmAlgorithm, HashAlgorithmName expectedHashAlgorithmName)
    {
        // Act
        var result = TmpHashAlgorithmMapper.Get(tpmAlgorithm);

        // Assert
        Assert.That(result, Is.EqualTo(expectedHashAlgorithmName));
    }

    private static IEnumerable<TestCaseData> HashAlgorithmTestCases()
    {
        yield return new TestCaseData(TpmAlgorithm.TpmAlgorithmSha1, HashAlgorithmName.SHA1);
        yield return new TestCaseData(TpmAlgorithm.TpmAlgorithmSha256, HashAlgorithmName.SHA256);
        yield return new TestCaseData(TpmAlgorithm.TpmAlgorithmSha384, HashAlgorithmName.SHA384);
        yield return new TestCaseData(TpmAlgorithm.TpmAlgorithmSha512, HashAlgorithmName.SHA512);
    }
}
