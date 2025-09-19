using System.Text.Json;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Tests.Models;

[TestFixture]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1861:Avoid constant arrays as arguments", Justification = "For improved unit test readability")]
internal class MetadataBlobPayloadEntryTests
{
    [Test]
    public void MetadataBlobPayloadEntry_WhenWindowsHelloHardwareAuthenticator_ThenReturnsCorrectObject()
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

    [Test]
    public void MetadataBlobPayloadEntry_WhenFullySet_ThenReturnsCorrectObject()
    {
        // Act
        var entry = new MetadataBlobPayloadEntry
        {
            Aaid = "test-aaid-12345",
            Aaguid = Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96"),
            AttestationCertificateKeyIdentifiers = ["key-id-1", "key-id-2"],
            BiometricStatusReports =
            [
                new BiometricStatusReport
                {
                    CertLevel = 1,
                    Modality = "fingerprint",
                    EffectiveDate = "2023-01-01",
                    CertificationDescriptor = "Test Biometric Certification",
                    CertificateNumber = "BIO-CERT-001",
                    CertificationPolicyVersion = "1.0.0",
                    CertificationRequirementsVersion = "1.0.0",
                },
            ],
            RogueListURL = "https://example.com/rogue-list",
            RogueListHash = "abc123def456",
            TimeOfLastStatusChange = "2023-12-01",
            StatusReports =
            [
                new StatusReport
                {
                    Status = "FIDO_CERTIFIED_L1",
                    EffectiveDate = "2023-01-01",
                    AuthenticatorVersion = 12345,
                    Certificate = "test-certificate-data",
                    Url = "https://example.com/status",
                    CertificationDescriptor = "Test Hardware Authenticator",
                    CertificateNumber = "FIDO20230101001",
                    CertificationPolicyVersion = "2.0.0",
                    CertificationRequirementsVersion = "1.5.0",
                },
                new StatusReport
                {
                    Status = "FIDO_CERTIFIED",
                    EffectiveDate = "2023-06-01",
                    AuthenticatorVersion = 12346,
                    Certificate = "test-certificate-data-2",
                    Url = "https://example.com/status-2",
                    CertificationDescriptor = "Test Software Authenticator",
                    CertificateNumber = "FIDO20230601002",
                    CertificationPolicyVersion = "2.1.0",
                    CertificationRequirementsVersion = "1.6.0",
                },
            ],
            MetadataStatement = new MetadataStatement
            {
                LegalHeader = "Test legal header for metadata statement",
                Aaid = "test-metadata-aaid",
                Aaguid = Guid.Parse("12345678-1234-5678-9abc-123456789abc"),
                AttestationCertificateKeyIdentifiers = ["meta-key-1", "meta-key-2"],
                Description = "Test Authenticator Description",
                AlternativeDescriptions = new Dictionary<string, string>
                {
                    { "en", "Test Authenticator" },
                    { "es", "Autenticador de Prueba" },
                    { "fr", "Authentificateur de Test" },
                },
                AuthenticatorVersion = 54321,
                ProtocolFamily = "fido2",
                Schema = 3,
                Upv =
                [
                    new UnifiedProtocolVersion { Major = 1, Minor = 0 },
                    new UnifiedProtocolVersion { Major = 1, Minor = 1 },
                ],
                AuthenticationAlgorithms = ["rsassa_pkcsv15_sha256_raw", "ecdsa_p256_sha256_raw"],
                PublicKeyAlgAndEncodings = ["cose", "jwk"],
                AttestationTypes = ["basic_full", "basic_surrogate", "attca"],
                UserVerificationDetails =
                [
                    [
                        new VerificationMethodDescriptor
                        {
                            UserVerificationMethod = "fingerprint_internal",
                            CaDesc = new CodeAccuracyDescriptor
                            {
                                SystemBase = 1,
                                MinLength = 4,
                                MaxRetries = 5,
                                BlockSlowdown = 30,
                            },
                            BaDesc = new BiometricAccuracyDescriptor
                            {
                                SelfAttestedFRR = 0.01,
                                SelfAttestedFAR = 0.0001,
                                MaxTemplates = 10,
                                MaxRetries = 5,
                                BlockSlowdown = 30,
                            },
                            PaDesc = new PatternAccuracyDescriptor
                            {
                                MinComplexity = 3,
                                MaxRetries = 5,
                                BlockSlowdown = 30,
                            },
                        },
                    ],
                    [
                        new VerificationMethodDescriptor
                        {
                            UserVerificationMethod = "faceprint_internal",
                            CaDesc = null,
                            BaDesc = null,
                            PaDesc = null,
                        },
                    ],
                ],
                KeyProtection = ["hardware", "tee"],
                IsKeyRestricted = true,
                IsFreshUserVerificationRequired = false,
                MatcherProtection = ["tee", "software"],
                CryptoStrength = 128,
                AttachmentHint = ["internal", "external"],
                TcDisplay = ["any", "privileged_software"],
                TcDisplayContentType = "text/plain",
                TcDisplayPNGCharacteristics =
                [
                    new DisplayPngCharacteristicsDescriptor
                    {
                        Width = 64,
                        Height = 64,
                        BitDepth = 24,
                        ColorType = 2,
                        Compression = 0,
                        Filter = 0,
                        Interlace = 0,
                        Plte =
                        [
                            new RgbPaletteEntry { Red = 0, Green = 255, Blue = 0 },
                        ],
                    },
                ],
                AttestationRootCertificates = ["root-cert-1", "root-cert-2"],
                EcdaaTrustAnchors =
                [
                    new EcdaaTrustAnchor
                    {
                        X = "base64url-encoded-x-coordinate",
                        Y = "base64url-encoded-y-coordinate",
                        C = "US",
                        Sx = "Sx",
                        Sy = "Sy",
                        G1Curve = "P-256",
                    },
                ],
                Icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
                SupportedExtensions =
                [
                    new ExtensionDescriptor
                    {
                        Id = "ext-1",
                        Tag = 1,
                        Data = "ext-1-data",
                        FailIfUnknown = true,
                    },
                ],
                AuthenticatorGetInfo = new Dictionary<string, object>
                {
                    { "versions", new[] { "FIDO_2_0", "FIDO_2_1" } },
                    { "maxMsgSize", 1200 },
                    { "pinUvAuthProtocols", new[] { 1, 2 } },
                },
            },
        };

        // Assert
        Assert.That(entry, Is.Not.Null);

        // MetadataBlobPayloadEntry properties
        Assert.That(entry.Aaid, Is.EqualTo("test-aaid-12345"));
        Assert.That(entry.Aaguid, Is.EqualTo(Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96")));
        Assert.That(entry.AttestationCertificateKeyIdentifiers, Is.EqualTo(["key-id-1", "key-id-2"]));
        Assert.That(entry.BiometricStatusReports, Has.Length.EqualTo(1));
        Assert.That(entry.RogueListURL, Is.EqualTo("https://example.com/rogue-list"));
        Assert.That(entry.RogueListHash, Is.EqualTo("abc123def456"));
        Assert.That(entry.TimeOfLastStatusChange, Is.EqualTo("2023-12-01"));
        Assert.That(entry.StatusReports, Has.Length.EqualTo(2));
        Assert.That(entry.ToString(), Is.EqualTo("Test Authenticator Description"));

        // BiometricStatusReport
        Assert.That(entry.BiometricStatusReports[0].CertLevel, Is.EqualTo(1));
        Assert.That(entry.BiometricStatusReports[0].Modality, Is.EqualTo("fingerprint"));
        Assert.That(entry.BiometricStatusReports[0].EffectiveDate, Is.EqualTo("2023-01-01"));
        Assert.That(entry.BiometricStatusReports[0].CertificationDescriptor, Is.EqualTo("Test Biometric Certification"));
        Assert.That(entry.BiometricStatusReports[0].CertificateNumber, Is.EqualTo("BIO-CERT-001"));
        Assert.That(entry.BiometricStatusReports[0].CertificationPolicyVersion, Is.EqualTo("1.0.0"));
        Assert.That(entry.BiometricStatusReports[0].CertificationRequirementsVersion, Is.EqualTo("1.0.0"));

        // First StatusReport
        Assert.That(entry.StatusReports[0].Status, Is.EqualTo("FIDO_CERTIFIED_L1"));
        Assert.That(entry.StatusReports[0].EffectiveDate, Is.EqualTo("2023-01-01"));
        Assert.That(entry.StatusReports[0].AuthenticatorVersion, Is.EqualTo(12345ul));
        Assert.That(entry.StatusReports[0].Certificate, Is.EqualTo("test-certificate-data"));
        Assert.That(entry.StatusReports[0].Url, Is.EqualTo("https://example.com/status"));
        Assert.That(entry.StatusReports[0].CertificationDescriptor, Is.EqualTo("Test Hardware Authenticator"));
        Assert.That(entry.StatusReports[0].CertificateNumber, Is.EqualTo("FIDO20230101001"));
        Assert.That(entry.StatusReports[0].CertificationPolicyVersion, Is.EqualTo("2.0.0"));
        Assert.That(entry.StatusReports[0].CertificationRequirementsVersion, Is.EqualTo("1.5.0"));

        // Second StatusReport
        Assert.That(entry.StatusReports[1].Status, Is.EqualTo("FIDO_CERTIFIED"));
        Assert.That(entry.StatusReports[1].EffectiveDate, Is.EqualTo("2023-06-01"));
        Assert.That(entry.StatusReports[1].AuthenticatorVersion, Is.EqualTo(12346ul));
        Assert.That(entry.StatusReports[1].Certificate, Is.EqualTo("test-certificate-data-2"));
        Assert.That(entry.StatusReports[1].Url, Is.EqualTo("https://example.com/status-2"));
        Assert.That(entry.StatusReports[1].CertificationDescriptor, Is.EqualTo("Test Software Authenticator"));
        Assert.That(entry.StatusReports[1].CertificateNumber, Is.EqualTo("FIDO20230601002"));
        Assert.That(entry.StatusReports[1].CertificationPolicyVersion, Is.EqualTo("2.1.0"));
        Assert.That(entry.StatusReports[1].CertificationRequirementsVersion, Is.EqualTo("1.6.0"));

        // MetadataStatement properties
        Assert.That(entry.MetadataStatement, Is.Not.Null);
        Assert.That(entry.MetadataStatement.LegalHeader, Is.EqualTo("Test legal header for metadata statement"));
        Assert.That(entry.MetadataStatement.Aaid, Is.EqualTo("test-metadata-aaid"));
        Assert.That(entry.MetadataStatement.Aaguid, Is.EqualTo(Guid.Parse("12345678-1234-5678-9abc-123456789abc")));
        Assert.That(entry.MetadataStatement.AttestationCertificateKeyIdentifiers, Is.EqualTo(["meta-key-1", "meta-key-2"]));
        Assert.That(entry.MetadataStatement.Description, Is.EqualTo("Test Authenticator Description"));
        Assert.That(entry.MetadataStatement.AlternativeDescriptions, Has.Count.EqualTo(3));
        Assert.That(entry.MetadataStatement.AlternativeDescriptions["en"], Is.EqualTo("Test Authenticator"));
        Assert.That(entry.MetadataStatement.AlternativeDescriptions["es"], Is.EqualTo("Autenticador de Prueba"));
        Assert.That(entry.MetadataStatement.AlternativeDescriptions["fr"], Is.EqualTo("Authentificateur de Test"));
        Assert.That(entry.MetadataStatement.AuthenticatorVersion, Is.EqualTo(54321ul));
        Assert.That(entry.MetadataStatement.ProtocolFamily, Is.EqualTo("fido2"));
        Assert.That(entry.MetadataStatement.Schema, Is.EqualTo(3));
        Assert.That(entry.MetadataStatement.Upv, Has.Length.EqualTo(2));
        Assert.That(entry.MetadataStatement.Upv[0].Major, Is.EqualTo(1));
        Assert.That(entry.MetadataStatement.Upv[0].Minor, Is.EqualTo(0));
        Assert.That(entry.MetadataStatement.Upv[1].Major, Is.EqualTo(1));
        Assert.That(entry.MetadataStatement.Upv[1].Minor, Is.EqualTo(1));
        Assert.That(entry.MetadataStatement.AuthenticationAlgorithms, Is.EqualTo(["rsassa_pkcsv15_sha256_raw", "ecdsa_p256_sha256_raw"]));
        Assert.That(entry.MetadataStatement.PublicKeyAlgAndEncodings, Is.EqualTo(["cose", "jwk"]));
        Assert.That(entry.MetadataStatement.AttestationTypes, Is.EqualTo(["basic_full", "basic_surrogate", "attca"]));
        Assert.That(entry.MetadataStatement.UserVerificationDetails, Has.Count.EqualTo(2));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0], Has.Length.EqualTo(1));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].UserVerificationMethod, Is.EqualTo("fingerprint_internal"));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].CaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].BaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[0][0].PaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[1], Has.Length.EqualTo(1));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[1][0].UserVerificationMethod, Is.EqualTo("faceprint_internal"));
        Assert.That(entry.MetadataStatement.UserVerificationDetails[1][0].CaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[1][0].BaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.UserVerificationDetails[1][0].PaDesc, Is.Null);
        Assert.That(entry.MetadataStatement.KeyProtection, Is.EqualTo(["hardware", "tee"]));
        Assert.That(entry.MetadataStatement.IsKeyRestricted, Is.True);
        Assert.That(entry.MetadataStatement.IsFreshUserVerificationRequired, Is.False);
        Assert.That(entry.MetadataStatement.MatcherProtection, Is.EqualTo(["tee", "software"]));
        Assert.That(entry.MetadataStatement.CryptoStrength, Is.EqualTo(128));
        Assert.That(entry.MetadataStatement.AttachmentHint, Is.EqualTo(["internal", "external"]));
        Assert.That(entry.MetadataStatement.TcDisplay, Is.EqualTo(["any", "privileged_software"]));
        Assert.That(entry.MetadataStatement.TcDisplayContentType, Is.EqualTo("text/plain"));
        Assert.That(entry.MetadataStatement.TcDisplayPNGCharacteristics, Is.Null);
        Assert.That(entry.MetadataStatement.AttestationRootCertificates, Is.EqualTo(["root-cert-1", "root-cert-2"]));
        Assert.That(entry.MetadataStatement.EcdaaTrustAnchors, Is.Null);
        Assert.That(entry.MetadataStatement.Icon, Is.EqualTo("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="));
        Assert.That(entry.MetadataStatement.SupportedExtensions, Is.Null);
        Assert.That(entry.MetadataStatement.AuthenticatorGetInfo, Is.Not.Null);
        Assert.That(entry.MetadataStatement.AuthenticatorGetInfo["versions"], Is.EqualTo(["FIDO_2_0", "FIDO_2_1"]));
        Assert.That(entry.MetadataStatement.AuthenticatorGetInfo["maxMsgSize"], Is.EqualTo(1200));
        Assert.That(entry.MetadataStatement.AuthenticatorGetInfo["pinUvAuthProtocols"], Is.EqualTo([1, 2]));
        Assert.That(entry.MetadataStatement.ToString(), Is.EqualTo("Test Authenticator Description"));
    }
}