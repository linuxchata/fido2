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
    private readonly ICertificateAttestationStatementValidator _certificateValidator;

    public PackedAttestationStatementStategy(
        IAlgorithmAttestationStatementValidator algorithmAttestationStatementValidator,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator)
    {
        _algorithmValidator = algorithmAttestationStatementValidator;
        _signatureValidator = signatureAttestationStatementValidator;
        _certificateValidator = certificateAttestationStatementValidator;
    }

    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        var attestationStatement = attestationObjectData.AttestationStatement ??
            throw new ArgumentNullException(nameof(attestationObjectData));

        if (attestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        if (_certificateValidator.IsCertificatePresent(attestationStatementDict))
        {
            // If x5c is present

            // Verify that sig is a valid signature over the concatenation of authenticatorData and
            // clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
            // TODO: Check whether alg is correct (attestation public key in attestnCert with the algorithm specified in alg.)
            var result = _signatureValidator.Validate(
                attestationStatementDict,
                credentialPublicKey,
                attestationObjectData.AuthenticatorRawData,
                clientData.ClientDataHash);
            if (!result.IsValid)
            {
                return result;
            }

            // Verify that attestnCert meets the requirements.
            result = _certificateValidator.Validate(attestationStatementDict, attestationObjectData);
            if (!result.IsValid)
            {
                return result;
            }
        }
        else
        {
            // If x5c is not present, self attestation is in use.

            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            var result = _algorithmValidator.Validate(attestationStatementDict, credentialPublicKey);
            if (!result.IsValid)
            {
                return result;
            }

            // Verify that sig is a valid signature over the concatenation of authenticatorData and
            // clientDataHash using the credential public key with alg.
            result = _signatureValidator.Validate(
                attestationStatementDict,
                credentialPublicKey,
                attestationObjectData.AuthenticatorRawData,
                clientData.ClientDataHash);
            if (!result.IsValid)
            {
                return result;
            }

            // If successful, return implementation-specific values representing attestation
            // type Self and an empty attestation trust path.
        }

        return ValidatorInternalResult.Invalid("Invalid attestation statement");
    }
}
