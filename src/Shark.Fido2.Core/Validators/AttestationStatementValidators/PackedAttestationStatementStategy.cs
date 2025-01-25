using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.2. Packed Attestation Statement Format
/// </summary>
internal class PackedAttestationStatementStategy : IAttestationStatementStategy
{
    private readonly IAlgorithmAttestationStatementValidator _algorithmValidator;
    private readonly ISignatureAttestationStatementValidator _signatureValidator;

    public PackedAttestationStatementStategy(
        IAlgorithmAttestationStatementValidator algorithmAttestationStatementValidator,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator)
    {
        _algorithmValidator = algorithmAttestationStatementValidator;
        _signatureValidator = signatureAttestationStatementValidator;
    }

    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        var attestationStatement = attestationObjectData.AttestationStatement;
        if (attestationStatement == null)
        {
            throw new ArgumentNullException(nameof(attestationObjectData));
        }

        if (attestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
        var result = _algorithmValidator.Validate(attestationStatementDict, credentialPublicKey);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that sig is a valid signature over the concatenation of authenticatorData and
        // clientDataHash using the credential public key with alg.
        result = _signatureValidator.Validate(attestationObjectData.AuthenticatorRawData, clientData.ClientDataHash, attestationStatementDict, credentialPublicKey);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that attestnCert meets the requirements
        if (!attestationStatementDict.TryGetValue("x5c", out var certificates) || certificates is not List<object>)
        {
            return ValidatorInternalResult.Invalid("Attestation certificates x5c cannot be read");
        }

        var attestationCertificate = ((List<object>)certificates)[0];
        var x509AttestationCertificate = new X509Certificate2((byte[])attestationCertificate);

        // Version MUST be set to 3
        if (x509AttestationCertificate.Version != 3)
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate unexpected version");
        }

        // Subject field MUST be set
        var distinguishedNames = x509AttestationCertificate.SubjectName.EnumerateRelativeDistinguishedNames();
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

        if (!distinguishedNamesMap.TryGetValue("C", out var country) ||
            string.IsNullOrWhiteSpace(country))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate subject is invalid");
        }

        if (!distinguishedNamesMap.TryGetValue("O", out var organization) ||
            string.IsNullOrWhiteSpace(organization))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate subject is invalid");
        }

        if (!distinguishedNamesMap.TryGetValue("OU", out var organizationalUnit) ||
            string.Equals(organizationalUnit, "Authenticator Attestation", StringComparison.Ordinal))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate subject is invalid");
        }

        if (!distinguishedNamesMap.TryGetValue("CN", out var commonName) ||
            string.IsNullOrWhiteSpace(commonName))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificate subject is invalid");
        }

        // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the aaguid in authenticatorData.
        var idFidoGenCeAaguid = x509AttestationCertificate.Extensions?
            .FirstOrDefault(a => a.Oid?.Value == "1.3.6.1.4.1.45724.1.1.4");
        if (idFidoGenCeAaguid != null)
        {
            if (idFidoGenCeAaguid.Critical)
            {
                return ValidatorInternalResult.Invalid(
                    "Attestation statement certificate extenstion 1.3.6.1.4.1.45724.1.1.4 must not be be marked as critical");
            }

            var aaGuid = new Guid(idFidoGenCeAaguid.RawData);
            if (aaGuid != attestationObjectData.AuthenticatorData.AttestedCredentialData.AaGuid)
            {
                return ValidatorInternalResult.Invalid("Attestation statement aaguid mismatch");
            }
        }

        return ValidatorInternalResult.Invalid("Invalid attestation statement");
    }
}
