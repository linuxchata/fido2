using Shark.Fido2.Metadata.Core.Mappers;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Tests.Mappers;

[TestFixture]
internal class MetadataPayloadItemMapperTests
{
    [Test]
    public void ToDomain_WhenEntryIsNull_ThenReturnsNull()
    {
        // Arrange
        MetadataBlobPayloadEntry? entry = null;

        // Act
        var result = entry.ToDomain();

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void ToDomain_WhenEntryIsValid_ThenMapsAllProperties()
    {
        // Arrange
        var entry = new MetadataBlobPayloadEntry
        {
            Aaguid = Guid.NewGuid(),
            MetadataStatement = new MetadataStatement
            {
                Description = "Test Authenticator",
                AttestationTypes = ["basic", "self"],
                ProtocolFamily = "FIDO2",
                Upv = [new UnifiedProtocolVersion { Major = 1, Minor = 0 }],
                AuthenticationAlgorithms = ["alg1", "alg2"],
                PublicKeyAlgAndEncodings = ["encoding1", "encoding2"],
                UserVerificationDetails = [],
                KeyProtection = ["software", "hardware"],
                MatcherProtection = ["tpm"],
                TcDisplay = ["any"],
                AttestationRootCertificates = ["cert1", "cert2"],
            },
            StatusReports =
            [
                new Models.StatusReport
                {
                    Status = "FIDO_CERTIFIED",
                    EffectiveDate = DateTime.UtcNow.ToString(),
                },
            ],
            TimeOfLastStatusChange = DateTime.UtcNow.ToString(),
        };

        // Act
        var result = entry.ToDomain();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Aaguid, Is.EqualTo(entry.Aaguid));
            Assert.That(result.Description, Is.EqualTo(entry.MetadataStatement.Description));
            Assert.That(result.AttestationTypes, Is.EqualTo(entry.MetadataStatement.AttestationTypes));
            Assert.That(result.StatusReports, Has.Length.EqualTo(1));
            Assert.That(result.StatusReports[0].Status, Is.EqualTo(entry.StatusReports[0].Status));
            Assert.That(result.StatusReports[0].EffectiveDate, Is.EqualTo(entry.StatusReports[0].EffectiveDate));
        });
    }

    [Test]
    public void ToDomain_WhenMetadataStatementIsNull_ThenMapsWithDefaultValues()
    {
        // Arrange
        var entry = new MetadataBlobPayloadEntry
        {
            Aaguid = Guid.NewGuid(),
            MetadataStatement = null,
            StatusReports = [],
            TimeOfLastStatusChange = DateTime.UtcNow.ToString(),
        };

        // Act
        var result = entry.ToDomain();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Aaguid, Is.EqualTo(entry.Aaguid));
            Assert.That(result.Description, Is.Null);
            Assert.That(result.AttestationTypes, Is.Empty);
            Assert.That(result.StatusReports, Is.Empty);
        });
    }
}
