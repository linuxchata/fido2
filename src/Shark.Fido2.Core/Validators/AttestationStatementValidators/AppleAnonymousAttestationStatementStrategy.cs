using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the Apple Anonymous attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.8.
/// See: https://www.w3.org/TR/webauthn/#sctn-apple-anonymous-attestation
/// </summary>
internal class AppleAnonymousAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICertificateAttestationStatementValidator _certificateAttestationStatementValidator;
    private readonly ICertificatePublicKeyValidator _certificatePublicKeyValidator;

    public AppleAnonymousAttestationStatementStrategy(
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator,
        ICertificatePublicKeyValidator certificatePublicKeyValidator)
    {
        _certificateProvider = certificateAttestationStatementProvider;
        _certificateAttestationStatementValidator = certificateAttestationStatementValidator;
        _certificatePublicKeyValidator = certificatePublicKeyValidator;
    }

    /// <summary>
    /// Validates an Apple Anonymous attestation statement.
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
            throw new ArgumentException(
                "Apple Anonymous attestation statement cannot be read",
                nameof(attestationObjectData));
        }

        // Concatenate authenticatorData and clientDataHash to form nonceToHash.
        var nonceToHash = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        // Perform SHA-256 hash of nonceToHash to produce nonce.
        var nonce = HashProvider.GetHash(nonceToHash, HashAlgorithmName.SHA256);

        // Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
        var certificates = _certificateProvider.GetCertificates(attestationStatementDict);
        var attestationCertificate = _certificateProvider.GetAttestationCertificate(certificates);

        var result = _certificateAttestationStatementValidator.ValidateAppleAnonymous(attestationCertificate, nonce);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that the credential public key equals the Subject Public Key of credCert.
        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;
        result = _certificatePublicKeyValidator.Validate(attestationCertificate, credentialPublicKey);
        if (!result.IsValid)
        {
            return result;
        }

        // If successful, return implementation-specific values representing attestation type Anonymization CA
        // and attestation trust path x5c.
        return new AttestationStatementInternalResult(AttestationTypeEnum.AnonCA, [.. certificates]);
    }
}
