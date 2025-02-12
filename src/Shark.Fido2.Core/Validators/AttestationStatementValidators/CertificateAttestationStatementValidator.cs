using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Dictionaries;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

internal class CertificateAttestationStatementValidator : ICertificateAttestationStatementValidator
{
    private const string IdFidoGenCeAaguidExtension = "1.3.6.1.4.1.45724.1.1.4";
    private const string JointIsoItuTExtension = "2.23.133.8.3";
    private const string BasicConstraintsExtension = "2.5.29.19";
    private const string EnhancedKeyUsageExtension = "2.5.29.37";
    private const string SubjectAlternativeNameExtension = "2.5.29.17";

    private const string SubjectCountry = "C";
    private const string SubjectOrganization = "O";
    private const string SubjectOrganizationalUnit = "OU";
    private const string SubjectCommonName = "CN";

    private const string OrganizationalUnitAuthenticatorAttestation = "Authenticator Attestation";

    private readonly ISubjectAlternativeNameParserService _subjectAlternativeNameParserService;

    public CertificateAttestationStatementValidator(
        ISubjectAlternativeNameParserService subjectAlternativeNameParserService)
    {
        _subjectAlternativeNameParserService = subjectAlternativeNameParserService;
    }

    public ValidatorInternalResult ValidatePacked(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData)
    {
        ArgumentNullException.ThrowIfNull(attestationCertificate);
        ArgumentNullException.ThrowIfNull(attestationObjectData);

        // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate Requirements.

        // Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        if (attestationCertificate.Version != 3)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate has unexpected version");
        }

        // Subject field MUST be set.
        var isCertificateSubjectValid = VerifyCertificateSubject(attestationCertificate);
        if (!isCertificateSubjectValid)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate subject is invalid");
        }

        // If the related attestation root certificate is used for multiple authenticator models, the Extension OID
        // 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte
        // OCTET STRING.
        // TODO: How check for multiple authenticator models?
        var idFidoGenCeAaguid = attestationCertificate.Extensions?.FirstOrDefault(
            e => string.Equals(e.Oid?.Value, IdFidoGenCeAaguidExtension, StringComparison.Ordinal));
        if (idFidoGenCeAaguid != null)
        {
            // The extension MUST NOT be marked as critical.
            if (idFidoGenCeAaguid.Critical)
            {
                return ValidatorInternalResult.Invalid(
                    $"Attestation statement certificate extenstion {IdFidoGenCeAaguidExtension} is marked as critical");
            }
        }

        // The Basic Constraints extension MUST have the CA component set to false.
        var basicConstraints = GetBasicConstraints(attestationCertificate);
        if (basicConstraints == null || basicConstraints.CertificateAuthority)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate authority is invalid");
        }

        // TODO: An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point
        // extension [RFC5280] are both OPTIONAL as the status  of many attestation certificates is available through
        // authenticator metadata  services. See, for example, the FIDO Metadata Service [FIDOMetadataService].

        // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
        // the value of this extension matches the aaguid in authenticatorData.
        if (idFidoGenCeAaguid != null)
        {
            var aaGuid = ParseGuidFromOctetString(idFidoGenCeAaguid.RawData);
            if (aaGuid != attestationObjectData.AuthenticatorData!.AttestedCredentialData.AaGuid)
            {
                return ValidatorInternalResult.Invalid("Attestation statement AAGUID mismatch");
            }
        }

        return ValidatorInternalResult.Valid();
    }

    public ValidatorInternalResult ValidateTpm(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData)
    {
        ArgumentNullException.ThrowIfNull(attestationCertificate);
        ArgumentNullException.ThrowIfNull(attestationObjectData);

        // Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.

        // Version MUST be set to 3.
        if (attestationCertificate.Version != 3)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate has unexpected version");
        }

        // Subject field MUST be set to empty.
        if (!string.IsNullOrWhiteSpace(attestationCertificate.SubjectName?.Name))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate has not empty subject");
        }

        // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        var subjectAlternativeNameExtension = attestationCertificate.Extensions?
            .FirstOrDefault(e => string.Equals(e.Oid?.Value, SubjectAlternativeNameExtension, StringComparison.Ordinal))
            as X509SubjectAlternativeNameExtension;
        if (subjectAlternativeNameExtension == null)
        {
            return ValidatorInternalResult.Invalid(
                "Attestation statement certificate subject alternative name is not found");
        }

        if (!subjectAlternativeNameExtension.Critical)
        {
            return ValidatorInternalResult.Invalid(
                $"Attestation statement certificate subject alternative name extenstion is not marked as critical");
        }

        var tpmIssuer = _subjectAlternativeNameParserService.Parse(subjectAlternativeNameExtension);

        // The TPM manufacturer MUST be the vendor ID defined in the TCG Vendor ID Registry
        if (!TpmCapabilitiesVendors.Exists(tpmIssuer!.ManufacturerValue))
        {
            return ValidatorInternalResult.Invalid(
                $"Attestation statement certificate subject alternative name has invalid TMP manufacturer {tpmIssuer.ManufacturerValue}");
        }

        if (string.IsNullOrWhiteSpace(tpmIssuer.Model))
        {
            return ValidatorInternalResult.Invalid(
                "Attestation statement certificate subject alternative name has invalid model");
        }

        if (string.IsNullOrWhiteSpace(tpmIssuer.Version))
        {
            return ValidatorInternalResult.Invalid(
                "Attestation statement certificate subject alternative name has invalid version");
        }

        // The Extended Key Usage extension MUST contain the OID 2.23.133.8.3
        // ("joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)").
        var enhancedKeyUsageExtension = attestationCertificate.Extensions?
            .FirstOrDefault(e => string.Equals(e.Oid?.Value, EnhancedKeyUsageExtension, StringComparison.Ordinal))
            as X509EnhancedKeyUsageExtension;
        if (enhancedKeyUsageExtension == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate enhanced key usage is not found");
        }

        var jointIsoItuTExtension = enhancedKeyUsageExtension.EnhancedKeyUsages[JointIsoItuTExtension];
        if (jointIsoItuTExtension == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate enhanced key usage is invalid");
        }

        // The Basic Constraints extension MUST have the CA component set to false.
        var basicConstraints = GetBasicConstraints(attestationCertificate);
        if (basicConstraints == null || basicConstraints.CertificateAuthority)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate authority is invalid");
        }

        // TODO: An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point
        // extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through
        // metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].

        // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
        // the value of this extension matches the aaguid in authenticatorData.
        var idFidoGenCeAaguid = attestationCertificate.Extensions?.FirstOrDefault(
            e => string.Equals(e.Oid?.Value, IdFidoGenCeAaguidExtension, StringComparison.Ordinal));
        if (idFidoGenCeAaguid != null)
        {
            var aaGuid = ParseGuidFromOctetString(idFidoGenCeAaguid.RawData);
            if (aaGuid != attestationObjectData.AuthenticatorData!.AttestedCredentialData.AaGuid)
            {
                return ValidatorInternalResult.Invalid("Attestation statement AAGUID mismatch");
            }
        }

        return ValidatorInternalResult.Valid();
    }

    public ValidatorInternalResult ValidateAndroidSafetyNet(X509Certificate2 attestationCertificate)
    {
        ArgumentNullException.ThrowIfNull(attestationCertificate);

        var isCertificateHostnameValid = VerifyCertificateHostname(attestationCertificate);
        if (!isCertificateHostnameValid)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate hostname is invalid");
        }

        return ValidatorInternalResult.Valid();
    }

    public ValidatorInternalResult ValidateChainOfTrustWithSystemCa(List<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);

        if (certificates.Count < 2)
        {
            return ValidatorInternalResult.Invalid("Attestation statement self-signed certificate is not supported");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = DateTime.Now;

        var leafCertificate = certificates.First();
        var intermediateCertificates = certificates.Skip(1).Take(certificates.Count - 2);

        foreach (var intermediateCertificate in intermediateCertificates)
        {
            chain.ChainPolicy.ExtraStore.Add(intermediateCertificate);
        }

        var isValid = chain.Build(leafCertificate);
        if (!isValid)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificates are invalid");
        }

        return ValidatorInternalResult.Valid();
    }

    private static bool VerifyCertificateSubject(X509Certificate2 certificate)
    {
        var distinguishedNamesMap = GetDistinguishedNames(certificate);

        // Subject-C
        // ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        if (!distinguishedNamesMap.TryGetValue(SubjectCountry, out var country) ||
            string.IsNullOrWhiteSpace(country))
        {
            return false;
        }

        // Subject-O
        // Legal name of the Authenticator vendor (UTF8String)
        if (!distinguishedNamesMap.TryGetValue(SubjectOrganization, out var organization) ||
            string.IsNullOrWhiteSpace(organization))
        {
            return false;
        }

        // Subject-OU
        // Literal string "Authenticator Attestation" (UTF8String)
        if (!distinguishedNamesMap.TryGetValue(SubjectOrganizationalUnit, out var organizationalUnit) ||
            !string.Equals(organizationalUnit, OrganizationalUnitAuthenticatorAttestation, StringComparison.Ordinal))
        {
            return false;
        }

        // Subject-CN
        // A UTF8String of the vendor's choosing
        if (!distinguishedNamesMap.TryGetValue(SubjectCommonName, out var commonName) ||
            string.IsNullOrWhiteSpace(commonName))
        {
            return false;
        }

        return true;
    }

    private static bool VerifyCertificateHostname(X509Certificate2 certificate)
    {
        var distinguishedNamesMap = GetDistinguishedNames(certificate);

        // Subject-CN
        if (!distinguishedNamesMap.TryGetValue(SubjectCommonName, out var commonName) ||
            !string.Equals(commonName, "attest.android.com", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static Dictionary<string, string?> GetDistinguishedNames(X509Certificate2 certificate)
    {
        var distinguishedNames = certificate.SubjectName.EnumerateRelativeDistinguishedNames();
        var distinguishedNamesMap = new Dictionary<string, string?>();
        foreach (var distinguishedName in distinguishedNames)
        {
            var type = distinguishedName.GetSingleElementType();
            var value = distinguishedName.GetSingleElementValue();
            if (!string.IsNullOrWhiteSpace(type.FriendlyName))
            {
                distinguishedNamesMap.Add(type.FriendlyName, value);
            }
        }

        return distinguishedNamesMap;
    }

    private static X509BasicConstraintsExtension? GetBasicConstraints(X509Certificate2 attestationCertificate)
    {
        return attestationCertificate.Extensions?
            .FirstOrDefault(e => string.Equals(e.Oid?.Value, BasicConstraintsExtension, StringComparison.Ordinal))
            as X509BasicConstraintsExtension;
    }

    private static Guid ParseGuidFromOctetString(byte[] data)
    {
        if (data == null || data.Length < 2)
        {
            throw new ArgumentException("Invalid certificate extension value (unexpected length)");
        }

        // Check whether octet string tag is 0x04
        if (data[0] != 0x04)
        {
            throw new ArgumentException("Invalid certificate extension value (unexpected octet string tag)");
        }

        // Extract octet string length byte and check that length is 16 bytes for GUID
        var length = data[1];
        if (length != 0x10)
        {
            throw new ArgumentException("Invalid certificate extension value (unexpected length)");
        }

        var guidBytes = new byte[length];
        Array.Copy(data, 2, guidBytes, 0, length);

        return new Guid(guidBytes);
    }
}
