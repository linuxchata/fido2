using System.Text.Json;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Tests.Models;

[TestFixture]
internal class MetadataBlobPayloadEntryTests
{
    [Test]
    public void DeserializeWindowsHelloHardwareAuthenticator_ShouldDeserializeCorrectly()
    {
        // Arrange
        var jsonContent = File.ReadAllText("Data/WindowsHelloHardwareAuthenticator.json");

        // Act
        var entry = JsonSerializer.Deserialize<MetadataBlobPayloadEntry>(jsonContent);

        // Assert
        Assert.That(entry, Is.Not.Null);

        // MetadataBlobPayloadEntry properties
        Assert.That(entry.Aaid, Is.Null);
        Assert.That(entry.Aaguid, Is.EqualTo(Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96")));
        Assert.That(entry.AttestationCertificateKeyIdentifiers, Is.Null);
        Assert.That(entry.BiometricStatusReports, Is.Null);
        Assert.That(entry.RogueListURL, Is.Null);
        Assert.That(entry.RogueListHash, Is.Null);
        Assert.That(entry.TimeOfLastStatusChange, Is.EqualTo("2020-08-05"));
        Assert.That(entry.StatusReports, Has.Length.EqualTo(2));
        Assert.That(entry.ToString(), Is.EqualTo("Windows Hello Hardware Authenticator"));

        // First StatusReport
        Assert.That(entry.StatusReports[0].Status, Is.EqualTo("FIDO_CERTIFIED_L1"));
        Assert.That(entry.StatusReports[0].EffectiveDate, Is.EqualTo("2020-08-05"));
        Assert.That(entry.StatusReports[0].AuthenticatorVersion, Is.Zero);
        Assert.That(entry.StatusReports[0].Certificate, Is.Null);
        Assert.That(entry.StatusReports[0].Url, Is.Null);
        Assert.That(entry.StatusReports[0].CertificationDescriptor, Is.EqualTo("Windows Hello Hardware Authenticator"));
        Assert.That(entry.StatusReports[0].CertificateNumber, Is.EqualTo("FIDO20020190418002"));
        Assert.That(entry.StatusReports[0].CertificationPolicyVersion, Is.EqualTo("1.3.6"));
        Assert.That(entry.StatusReports[0].CertificationRequirementsVersion, Is.EqualTo("1.1.0"));

        // Second StatusReport
        Assert.That(entry.StatusReports[1].Status, Is.EqualTo("FIDO_CERTIFIED"));
        Assert.That(entry.StatusReports[1].EffectiveDate, Is.EqualTo("2020-08-05"));
        Assert.That(entry.StatusReports[1].AuthenticatorVersion, Is.Zero);
        Assert.That(entry.StatusReports[1].Certificate, Is.Null);
        Assert.That(entry.StatusReports[1].Url, Is.Null);
        Assert.That(entry.StatusReports[1].CertificationDescriptor, Is.Null);
        Assert.That(entry.StatusReports[1].CertificateNumber, Is.Null);
        Assert.That(entry.StatusReports[1].CertificationPolicyVersion, Is.Null);
        Assert.That(entry.StatusReports[1].CertificationRequirementsVersion, Is.Null);

        // MetadataStatement properties
        Assert.That(entry.MetadataStatement, Is.Not.Null);
        Assert.That(entry.MetadataStatement.LegalHeader, Is.EqualTo("Submission of this statement and retrieval and use of this statement indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/."));
        Assert.That(entry.MetadataStatement.Aaid, Is.Null);
        Assert.That(entry.MetadataStatement.Aaguid, Is.EqualTo(Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96")));
        Assert.That(entry.MetadataStatement.AttestationCertificateKeyIdentifiers, Is.Null);
        Assert.That(entry.MetadataStatement.Description, Is.EqualTo("Windows Hello Hardware Authenticator"));
        Assert.That(entry.MetadataStatement.AlternativeDescriptions, Is.Null);
        Assert.That(entry.MetadataStatement.AuthenticatorVersion, Is.EqualTo(19042ul));
        Assert.That(entry.MetadataStatement.ProtocolFamily, Is.EqualTo("fido2"));
        Assert.That(entry.MetadataStatement.Schema, Is.EqualTo(3));
        Assert.That(entry.MetadataStatement.Upv, Has.Length.EqualTo(1));
        Assert.That(entry.MetadataStatement.Upv[0].Major, Is.EqualTo(1));
        Assert.That(entry.MetadataStatement.Upv[0].Minor, Is.Zero);
        Assert.That(entry.MetadataStatement.AuthenticationAlgorithms, Is.EqualTo(new[] { "rsassa_pkcsv15_sha256_raw" }));
        Assert.That(entry.MetadataStatement.PublicKeyAlgAndEncodings, Is.EqualTo(new[] { "cose" }));
        Assert.That(entry.MetadataStatement.AttestationTypes, Is.EqualTo(new[] { "basic_surrogate", "attca" }));
        Assert.That(entry.MetadataStatement.UserVerificationDetails, Has.Count.EqualTo(4));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0], Has.Length.EqualTo(1));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].UserVerificationMethod, Is.EqualTo("faceprint_internal"));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].CaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].BaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].PaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.KeyProtection, Is.EqualTo(new[] { "hardware" }));
        Assert.That(entry.MetadataStatement.IsKeyRestricted, Is.False);
        Assert.That(entry.MetadataStatement.IsFreshUserVerificationRequired, Is.Null);
        Assert.That(entry.MetadataStatement.MatcherProtection, Is.EqualTo(new[] { "software" }));
        Assert.That(entry.MetadataStatement.CryptoStrength, Is.Zero);
        Assert.That(entry.MetadataStatement.AttachmentHint, Is.EqualTo(new[] { "internal" }));
        Assert.That(entry.MetadataStatement.TcDisplay, Is.Empty);
        Assert.That(entry.MetadataStatement.TcDisplayContentType, Is.Null);
        Assert.That(entry.MetadataStatement.TcDisplayPNGCharacteristics, Is.Null);
        Assert.That(entry.MetadataStatement.AttestationRootCertificates, Has.Length.EqualTo(1));
        Assert.That(entry.MetadataStatement.EcdaaTrustAnchors, Is.Null);
        Assert.That(entry.MetadataStatement.Icon, Is.Not.Null);
        Assert.That(entry.MetadataStatement.SupportedExtensions, Is.Null);
        Assert.That(entry.MetadataStatement.AuthenticatorGetInfo, Is.Not.Null);
        Assert.That(entry.MetadataStatement.ToString(), Is.EqualTo("Windows Hello Hardware Authenticator"));
    }
}
