using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.2. Packed Attestation Statement Format
/// </summary>
internal class PackedAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly IAlgorithmAttestationStatementValidator _algorithmValidator;
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICertificateAttestationStatementValidator _certificateValidator;

    public PackedAttestationStatementStrategy(
        IAlgorithmAttestationStatementValidator algorithmAttestationStatementValidator,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator)
    {
        _algorithmValidator = algorithmAttestationStatementValidator;
        _signatureValidator = signatureAttestationStatementValidator;
        _certificateProvider = certificateAttestationStatementProvider;
        _certificateValidator = certificateAttestationStatementValidator;
    }

    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);
        ArgumentNullException.ThrowIfNull(creationOptions);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        var concatenatedData = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        // If x5c is present
        if (_certificateProvider.AreCertificatesPresent(attestationStatementDict))
        {
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the attestation public key in attestnCert with the algorithm specified in alg.
            var certificates = _certificateProvider.GetCertificates(attestationStatementDict);
            var attestationCertificate = _certificateProvider.GetAttestationCertificate(certificates);
            var result = _signatureValidator.Validate(
                concatenatedData,
                attestationStatementDict,
                credentialPublicKey,
                attestationCertificate);
            if (!result.IsValid)
            {
                return result;
            }

            // Verify that attestnCert meets the requirements in 8.2.1 Packed Attestation Statement Certificate Requirements.
            // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // verify that the value of this extension matches the aaguid in authenticatorData.
            result = _certificateValidator.ValidatePacked(attestationCertificate, attestationObjectData);
            if (!result.IsValid)
            {
                return result;
            }

            // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys
            // a Basic or AttCA attestation.
            var attestationType = (attestationCertificate.Subject == attestationCertificate.Issuer) ?
                AttestationTypeEnum.Basic : AttestationTypeEnum.AttCA;

            // If successful, return implementation-specific values representing attestation type Basic, AttCA or
            // uncertainty, and attestation trust path x5c.
            return new AttestationStatementInternalResult(attestationType, [.. certificates]);
        }
        // If x5c is not present, self attestation is in use.
        else
        {
            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            var result = _algorithmValidator.Validate(attestationStatementDict, credentialPublicKey);
            if (!result.IsValid)
            {
                return result;
            }

            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the credential public key with alg.
            result = _signatureValidator.Validate(concatenatedData, attestationStatementDict, credentialPublicKey);
            if (!result.IsValid)
            {
                return result;
            }

            // If successful, return implementation-specific values representing attestation type Self and an empty
            // attestation trust path.
            return new AttestationStatementInternalResult(AttestationTypeEnum.Self);
        }
    }
}
