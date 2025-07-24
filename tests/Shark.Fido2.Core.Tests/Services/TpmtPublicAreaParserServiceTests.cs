using Shark.Fido2.Core.Services;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class TpmtPublicAreaParserServiceTests
{
    private TpmtPublicAreaParserService _sut;

    [SetUp]
    public void Setup()
    {
        _sut = new TpmtPublicAreaParserService();
    }

    [Test]
    public void Parse_WhenPubAreaIsValidRsa_ThenReturnsTrue()
    {
        // Arrange
        var pubAreaBase64 = "AAEACwAGBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAEAgAAAAAAAEAxdpvTZNXveIC9cVYzQoxVtJU8uCtmrV5MfmCa3R94axPKdYHCHTc5XkQ4ZhESZ2OQkcDObFw0CK1AauI6cL07TAuRxnHDevohCQD7ZvfwicwphobcPYWxfG3AMrPeEYTfcSy1Gmo4VqrT62GVwhAItKPRNkHUyMSa3AHyYGTn99yTK9PvkdQQEMaTqBkQwvLLPrX0Fvbn2S1sOCVLs+GeSc9bG36gWAfFFAzFqE9B4LDGj5r3e09e8Rrwfqb7w3/g7ferxRrWCxGRIIaPGLtuqa+QivwTkPtr1/TeDCGFT1zYaIDBhpimKsm4TN8ocntBnQaWQVHeYjnIDBOrhidfw==";
        var pubArea = Convert.FromBase64String(pubAreaBase64);

        // Act
        var result = _sut.Parse(pubArea, out var tpmtPublic);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(tpmtPublic.Type, Is.EqualTo(TpmAlgorithm.TpmAlgorithmRsa));
        Assert.That(tpmtPublic.NameAlg, Is.EqualTo(TpmAlgorithm.TpmAlgorithmSha256));
        Assert.That(tpmtPublic.Unique, Is.Not.Null);
        Assert.That(tpmtPublic.Unique.Length, Is.EqualTo(256));
    }
}