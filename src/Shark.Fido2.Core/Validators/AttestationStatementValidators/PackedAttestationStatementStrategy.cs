﻿using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the Packed attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.2.
/// See: https://www.w3.org/TR/webauthn/#sctn-packed-attestation
/// </summary>
internal class PackedAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICertificateAttestationStatementValidator _certificateValidator;

    public PackedAttestationStatementStrategy(
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator)
    {
        _signatureValidator = signatureAttestationStatementValidator;
        _certificateProvider = certificateAttestationStatementProvider;
        _certificateValidator = certificateAttestationStatementValidator;
    }

    /// <summary>
    /// Validates a Packed attestation statement.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate</param>
    /// <param name="clientData">The client data associated with the attestation</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation statement is valid</returns>
    /// <exception cref="ArgumentNullException">Thrown when attestationObjectData or clientData is null</exception>
    /// <exception cref="ArgumentException">Thrown when attestation statement cannot be read</exception>
    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Packed attestation statement cannot be read", nameof(attestationObjectData));
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
            if (!attestationStatementDict.TryGetValue(AttestationStatement.Algorithm, out var algorithm) ||
                algorithm is not int)
            {
                return ValidatorInternalResult.Invalid("Packed attestation statement algorithm cannot be read");
            }

            if (credentialPublicKey.Algorithm != (int)algorithm)
            {
                return ValidatorInternalResult.Invalid(
                    $"Packed attestation statement algorithm ({algorithm}) does not match credential public key algorithm ({credentialPublicKey.Algorithm})");
            }

            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the credential public key with alg.
            var result = _signatureValidator.Validate(concatenatedData, attestationStatementDict, credentialPublicKey);
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
