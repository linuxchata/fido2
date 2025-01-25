using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal class CertificateAttestationStatementValidator : ICertificateAttestationStatementValidator
{
    private const string Certificate = "x5c";
    private const string IdFidoGenCeAaguidExtension = "1.3.6.1.4.1.45724.1.1.4";
    private const string BasicConstraintsExtension = "Basic Constraints";
    private const string SubjectCountry = "C";
    private const string SubjectOrganization = "O";
    private const string SubjectOrganizationalUnit = "OU";
    private const string SubjectCommonName = "CN";
    private const string OrganizationalUnitAuthenticatorAttestation = "Authenticator Attestation";

    public ValidatorInternalResult Validate(
        Dictionary<string, object> attestationStatementDict,
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData)
    {
        // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate Requirements.
        if (!attestationStatementDict.TryGetValue(Certificate, out var x5c) || x5c is not List<object>)
        {
            return ValidatorInternalResult.Invalid("Attestation certificates x5c cannot be read");
        }

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
        var basicConstraints = attestationCertificate.Extensions?
            .FirstOrDefault(e => string.Equals(e.Oid?.FriendlyName, BasicConstraintsExtension, StringComparison.Ordinal))
            as X509BasicConstraintsExtension;
        if (basicConstraints != null && basicConstraints.CertificateAuthority)
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

    private static bool VerifyCertificateSubject(X509Certificate2 certificate)
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

    private static Guid ParseGuidFromOctetString(byte[] data)
    {
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
